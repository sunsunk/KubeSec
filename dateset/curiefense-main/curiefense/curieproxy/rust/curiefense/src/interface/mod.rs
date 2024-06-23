use crate::config::hostmap::SecurityPolicy;
/// this file contains all the data type that are used when interfacing with a proxy
use crate::config::matchers::RequestSelector;
use crate::config::raw::{RawAction, RawActionType};
use crate::grasshopper::{challenge_phase01, GHMode, Grasshopper, PrecisionLevel};
use crate::logs::Logs;
use crate::utils::json::NameValue;
use crate::utils::templating::{parse_request_template, RequestTemplate, TVar, TemplatePart};
use crate::utils::{selector, GeoIp, RequestInfo, Selected};
use chrono::{DateTime, Duration, DurationRound};
use md5;
use serde::ser::{SerializeMap, SerializeSeq};
use serde::{Deserialize, Serialize, Serializer};
use std::collections::{HashMap, HashSet};

pub use self::block_reasons::*;
pub use self::stats::*;
pub use self::tagging::*;

pub mod aggregator;
pub mod block_reasons;
pub mod stats;
pub mod tagging;

#[derive(Debug, Clone)]
pub enum SimpleDecision {
    Pass,
    Action(SimpleAction, Vec<BlockReason>),
}

/// Merge two decisions together.
///
/// If the two decisions have differents priorities, returns the one with
/// the highest one.
/// If the two decisions have the same priority and have action of type
/// Monitor, returns the first one, with headers merged from the two
/// decisions
/// If the two decisions have the same priority, but not actions of type
/// Monitor, retunrs the first decision.
///
/// In all cases, block reasons are always merged.
///
/// Priorities of actions are: Skip > Block > Monitor > None
pub fn merge_decisions(d1: Decision, d2: Decision) -> Decision {
    // Choose which decision to keep, and which decision to throw away
    let (mut kept, thrown) = {
        match (&d1.maction, &d2.maction) {
            (Some(a1), Some(a2)) => {
                if a1.atype.priority() >= a2.atype.priority() {
                    (d1, d2)
                } else {
                    (d2, d1)
                }
            }
            (None, Some(_)) => (d2, d1),
            (Some(_), None) | (None, None) => (d1, d2),
        }
    };

    // Merge headers if kept action is monitor
    if let Some(action) = &mut kept.maction {
        if action.atype == ActionType::Monitor {
            // if the kept action is monitor, the thrown action is monitor or pass, so we might need to merge headers
            let throw_headers = thrown.maction.and_then(|action| action.headers);
            if let Some(headers) = &mut action.headers {
                headers.extend(throw_headers.unwrap_or_default())
            } else {
                action.headers = throw_headers;
            }
        }
    }

    kept.reasons.extend(thrown.reasons);

    kept
}

/// identical to merge_decisions, but for simple decisions
pub fn stronger_decision(d1: SimpleDecision, d2: SimpleDecision) -> SimpleDecision {
    match (d1, d2) {
        (SimpleDecision::Pass, d2) => d2,
        (d1, SimpleDecision::Pass) => d1,
        (SimpleDecision::Action(mut s1, mut kept_reasons), SimpleDecision::Action(s2, br2)) => {
            kept_reasons.extend(br2);
            if s1.atype.priority() > s2.atype.priority() {
                SimpleDecision::Action(s1, kept_reasons)
            } else if s1.atype == SimpleActionT::Monitor && s2.atype == SimpleActionT::Monitor {
                s1.headers = match (s1.headers, s2.headers) {
                    (None, None) => None,
                    (Some(h1), None) => Some(h1),
                    (None, Some(h2)) => Some(h2),
                    (Some(mut h1), Some(h2)) => {
                        h1.extend(h2);
                        Some(h1)
                    }
                };
                SimpleDecision::Action(s1, kept_reasons)
            } else {
                SimpleDecision::Action(s2, kept_reasons)
            }
        }
    }
}

#[derive(Debug)]
pub struct AnalyzeResult {
    pub decision: Decision,
    pub tags: Tags,
    pub rinfo: RequestInfo,
    pub stats: Stats,
}

#[derive(Debug, Clone)]
pub struct Decision {
    pub maction: Option<Action>,
    pub reasons: Vec<BlockReason>,
}

impl Decision {
    pub fn skip(id: String, name: String, initiator: Initiator, location: Location) -> Self {
        Decision {
            maction: None,
            reasons: vec![BlockReason {
                id,
                name,
                initiator,
                location,
                action: RawActionType::Skip,
                extra_locations: Vec::new(),
                extra: serde_json::Value::Null,
            }],
        }
    }

    pub fn pass(reasons: Vec<BlockReason>) -> Self {
        Decision { maction: None, reasons }
    }

    pub fn action(action: Action, reasons: Vec<BlockReason>) -> Self {
        Decision {
            maction: Some(action),
            reasons,
        }
    }

    /// is the action blocking (not passed to the underlying server)
    pub fn is_blocking(&self) -> bool {
        self.maction.as_ref().map(|a| a.atype.is_blocking()).unwrap_or(false)
    }

    pub fn blocked(&self) -> bool {
        for r in &self.reasons {
            if !(matches!(r.action, RawActionType::Monitor) || matches!(r.action, RawActionType::Skip)) {
                return true;
            }
        }
        false
    }

    /// is the action final (no further processing)
    pub fn is_final(&self) -> bool {
        self.maction.as_ref().map(|a| a.atype.is_final()).unwrap_or(false)
            || self.reasons.iter().any(|r| r.action.is_final())
    }

    pub fn response_json(&self) -> String {
        let action_desc = if self.is_blocking() { "custom_response" } else { "pass" };
        let response =
            serde_json::to_value(&self.maction).unwrap_or_else(|rr| serde_json::Value::String(rr.to_string()));
        let j = serde_json::json!({
            "action": action_desc,
            "response": response,
        });
        serde_json::to_string(&j).unwrap_or_else(|_| "{}".to_string())
    }

    pub async fn log_json(
        &self,
        rinfo: &RequestInfo,
        tags: &Tags,
        stats: &Stats,
        logs: &Logs,
        proxy: HashMap<String, String>,
    ) -> Vec<u8> {
        let (request_map, _) = jsonlog(
            self,
            Some(rinfo),
            self.maction.as_ref().map(|a| a.status),
            tags,
            stats,
            logs,
            proxy,
        )
        .await;
        request_map
    }
}

// helper function that reproduces the envoy log format
// this is the moment where we perform stats aggregation as we have the return code
pub async fn jsonlog(
    dec: &Decision,
    mrinfo: Option<&RequestInfo>,
    rcode: Option<u32>,
    tags: &Tags,
    stats: &Stats,
    logs: &Logs,
    proxy: HashMap<String, String>,
) -> (Vec<u8>, chrono::DateTime<chrono::Utc>) {
    let now = mrinfo.map(|i| i.timestamp).unwrap_or_else(chrono::Utc::now);
    let proxy_status = proxy.get("status").and_then(|stt_str| stt_str.parse().ok());
    let bytes_sent: Option<usize> = proxy.get("bytes_sent").and_then(|s| s.parse().ok());
    let status_code = if !dec.blocked() && proxy_status.is_some() {
        proxy_status
    } else {
        rcode.or_else(|| proxy_status)
    };
    match mrinfo {
        Some(rinfo) => {
            aggregator::aggregate(dec, status_code, rinfo, tags, bytes_sent).await;
            match jsonlog_rinfo(dec, rinfo, status_code, tags, stats, logs, proxy, &now) {
                Err(_) => (b"null".to_vec(), now),
                Ok(y) => (y, now),
            }
        }
        None => (b"null".to_vec(), now),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn jsonlog_rinfo(
    dec: &Decision,
    rinfo: &RequestInfo,
    mut rcode: Option<u32>,
    tags: &Tags,
    stats: &Stats,
    logs: &Logs,
    proxy: HashMap<String, String>,
    now: &chrono::DateTime<chrono::Utc>,
) -> serde_json::Result<Vec<u8>> {
    //block reason is for the single reason for the blocking of the request, if happened
    let block_reason_desc = if dec.is_final() {
        BlockReason::block_reason_desc(&dec.reasons)
    } else {
        None
    };
    let greasons = BlockReason::regroup(&dec.reasons);
    let get_trigger = |k: &InitiatorKind| -> &[&BlockReason] { greasons.get(k).map(|v| v.as_slice()).unwrap_or(&[]) };

    //monitor reason(s) is for the list of reasons for monitor action
    let monitor_reason_desc = BlockReason::monitor_reason_desc(&dec.reasons);

    let mut outbuffer = Vec::<u8>::new();
    let mut ser = serde_json::Serializer::new(&mut outbuffer);
    let mut map_ser = ser.serialize_map(None)?;
    map_ser.serialize_entry("timestamp", now)?;
    map_ser.serialize_entry(
        "timestamp_min",
        &now.duration_trunc(chrono::Duration::minutes(1)).unwrap(),
    )?;
    map_ser.serialize_entry("curiesession", &rinfo.session)?;
    //pulled up params from proxy map
    if let Some(val) = proxy.get("bytes_sent") {
        let bytes_sent = val.parse::<i32>().unwrap_or_default();
        map_ser.serialize_entry("bytes_sent", &bytes_sent)?;
    }
    if let Some(val) = proxy.get("request_time") {
        let request_time = val.parse::<f32>().unwrap_or_default();
        map_ser.serialize_entry("request_time", &request_time)?;
    }
    if let Some(val) = proxy.get("request_length") {
        let request_length = val.parse::<f32>().unwrap_or_default();
        map_ser.serialize_entry("request_length", &request_length)?;
    }
    if let Some(response_times) = proxy.get("upstream_response_time") {
        if let Some(statuses) = proxy.get("upstream_status") {
            if let Some(addresses) = proxy.get("upstream_addr") {
                let response_times = parse_values::<f32>(response_times);
                let statuses = parse_values::<i32>(statuses);
                let addresses = parse_values::<String>(addresses);

                let response_times_sum: f32 = response_times.iter().sum();
                map_ser.serialize_entry("upstream_response_time", &response_times_sum)?;
                map_ser.serialize_entry("upstream_status", &statuses)?;
                map_ser.serialize_entry("upstream_addr", &addresses)?;

                //add upstream_data only if all lists are the same length (no single field is missing)
                if response_times.len() == statuses.len() && response_times.len() == addresses.len() {
                    let upstream_data: Vec<_> = response_times
                        .into_iter()
                        .zip(statuses)
                        .zip(addresses)
                        .map(|((response_time, status), address)| {
                            serde_json::json!({
                                "response_time": format!("{:.3}", response_time),
                                "status": status,
                                "addr": address,
                            })
                        })
                        .collect();

                    map_ser.serialize_entry("upstream_data", &upstream_data)?;
                }
            }
        }
    }

    map_ser.serialize_entry("host", &rinfo.headers.get("host"))?;
    map_ser.serialize_entry("user_agent", &rinfo.headers.get("user-agent"))?;
    map_ser.serialize_entry("referer", &rinfo.headers.get("referer"))?;
    map_ser.serialize_entry("hostname", &rinfo.rinfo.container_name)?;
    map_ser.serialize_entry("protocol", &rinfo.headers.get("x-forwarded-proto"))?;
    map_ser.serialize_entry("port", &rinfo.headers.get("x-forwarded-port"))?;

    if let Some(rbzid) = rinfo.cookies.get("rbzid") {
        let digest = md5::compute(rbzid);
        let md5_rbzid = format!("{:x}", digest);
        map_ser.serialize_entry("rbzid", &md5_rbzid)?;
    }

    map_ser.serialize_entry("geo_region", &rinfo.rinfo.geoip.region)?;
    map_ser.serialize_entry("geo_country", &rinfo.rinfo.geoip.country_name)?;
    map_ser.serialize_entry("geo_org", &rinfo.rinfo.geoip.company)?;

    // pulled up from tags
    let mut has_monitor = false;
    let mut has_challenge = false;
    let mut has_ichallenge = false;
    let mut has_human = false;
    let mut has_bot = false;
    for t in tags.inner().keys() {
        if let Some(val) = t.strip_prefix("geo-asn:") {
            map_ser.serialize_entry("geo_asn", &val)?;
        }
        match t.as_str() {
            "action:monitor" => has_monitor = true,
            "human" => has_human = true,
            "bot" => has_bot = true,
            _ => {}
        }
    }
    if let Some(action) = &dec.maction {
        if let Some(tags) = &action.extra_tags {
            for t in tags {
                match t.as_str() {
                    "challenge" => has_challenge = true,
                    "ichallenge" => has_ichallenge = true,
                    _ => {}
                }
            }
        }
    }
    map_ser.serialize_entry("monitor", &has_monitor)?;
    map_ser.serialize_entry("challenge", &has_challenge)?;
    map_ser.serialize_entry("ichallenge", &has_ichallenge)?;
    map_ser.serialize_entry("human", &has_human)?;
    map_ser.serialize_entry("bot", &has_bot)?;

    map_ser.serialize_entry("curiesession_ids", &NameValue::new(&rinfo.session_ids))?;
    let request_id = proxy.get("request_id").or(rinfo.rinfo.meta.requestid.as_ref());
    map_ser.serialize_entry("request_id", &request_id)?;
    map_ser.serialize_entry("arguments", &rinfo.rinfo.qinfo.args)?;
    map_ser.serialize_entry("path", &rinfo.rinfo.qinfo.qpath)?;
    map_ser.serialize_entry("path_parts", &rinfo.rinfo.qinfo.path_as_map)?;
    map_ser.serialize_entry("authority", &rinfo.rinfo.host)?;
    map_ser.serialize_entry("cookies", &rinfo.cookies)?;
    map_ser.serialize_entry("headers", &rinfo.headers)?;
    if !rinfo.plugins.is_empty() {
        map_ser.serialize_entry("plugins", &rinfo.plugins)?;
    }
    map_ser.serialize_entry("query", &rinfo.rinfo.qinfo.query)?;
    map_ser.serialize_entry("ip", &rinfo.rinfo.geoip.ip)?;
    map_ser.serialize_entry("method", &rinfo.rinfo.meta.method)?;
    map_ser.serialize_entry("response_code", &rcode)?;

    map_ser.serialize_entry("logs", logs)?;
    map_ser.serialize_entry("processing_stage", &stats.processing_stage)?;

    map_ser.serialize_entry("acl_triggers", get_trigger(&InitiatorKind::Acl))?;
    map_ser.serialize_entry("rl_triggers", get_trigger(&InitiatorKind::RateLimit))?;
    map_ser.serialize_entry("gf_triggers", get_trigger(&InitiatorKind::GlobalFilter))?;
    map_ser.serialize_entry("cf_triggers", get_trigger(&InitiatorKind::ContentFilter))?;
    map_ser.serialize_entry("cf_restrict_triggers", get_trigger(&InitiatorKind::Restriction))?;
    map_ser.serialize_entry("reason", &block_reason_desc)?;
    map_ser.serialize_entry("monitor_reasons", &monitor_reason_desc)?;

    let branch_tag = tags.inner().keys().filter_map(|t| t.strip_prefix("branch:")).next();
    map_ser.serialize_entry("branch", &branch_tag)?;
    // it's too bad one can't directly write the recursive structures from just the serializer object
    // that's why there are several one shot structures for nested data:
    struct LogTags<'t> {
        tags: &'t Tags,
        extra: Option<&'t HashSet<String>>,
        rcode: Option<u32>,
    }
    impl<'t> Serialize for LogTags<'t> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut code_vec: Vec<(&str, String)> = Vec::new();
            if let Some(code) = self.rcode {
                code_vec.push(("status", format!("{}", code)));
                code_vec.push(("status-class", format!("{}xx", code / 100)));
            }

            self.tags.serialize_with_extra(
                serializer,
                self.extra.iter().flat_map(|i| i.iter().map(|s| s.as_str())),
                code_vec.into_iter(),
            )
        }
    }

    // If we have a monitor action, remove the return code to prevent tag
    // addition. This could be fixed with a better Action structure, but
    // requires more changes.
    if let Some(Action {
        atype: ActionType::Monitor,
        ..
    }) = &dec.maction
    {
        rcode = None;
    }
    // Do not log block action for non-blocking decision
    let blocked = dec.blocked();
    let mut filtered_tags = tags.clone();
    if !blocked && filtered_tags.contains("action:content-filter-block") {
        filtered_tags.tags.remove("action:content-filter-block");
    }

    map_ser.serialize_entry(
        "tags",
        &LogTags {
            tags: &filtered_tags,
            extra: dec.maction.as_ref().and_then(|a| a.extra_tags.as_ref()),
            rcode,
        },
    )?;

    struct LogProxy<'t> {
        p: &'t HashMap<String, String>,
        geo: &'t GeoIp,
        n: &'t Option<String>,
    }
    impl<'t> Serialize for LogProxy<'t> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut sq = serializer.serialize_seq(None)?;
            for (name, value) in self.p {
                sq.serialize_element(&crate::utils::json::BigTableKV { name, value })?;
            }
            sq.serialize_element(&crate::utils::json::BigTableKV {
                name: "geo_long",
                value: self.geo.location.as_ref().map(|x| x.0),
            })?;
            sq.serialize_element(&crate::utils::json::BigTableKV {
                name: "geo_lat",
                value: self.geo.location.as_ref().map(|x| x.1),
            })?;
            sq.serialize_element(&crate::utils::json::BigTableKV {
                name: "geo_as_name",
                value: self.geo.as_name.as_ref(),
            })?;
            sq.serialize_element(&crate::utils::json::BigTableKV {
                name: "geo_as_domain",
                value: self.geo.as_domain.as_ref(),
            })?;
            sq.serialize_element(&crate::utils::json::BigTableKV {
                name: "geo_as_type",
                value: self.geo.as_type.as_ref(),
            })?;
            sq.serialize_element(&crate::utils::json::BigTableKV {
                name: "geo_company_country",
                value: self.geo.company_country.as_ref(),
            })?;
            sq.serialize_element(&crate::utils::json::BigTableKV {
                name: "geo_company_domain",
                value: self.geo.company_domain.as_ref(),
            })?;
            sq.serialize_element(&crate::utils::json::BigTableKV {
                name: "geo_company_type",
                value: self.geo.company_type.as_ref(),
            })?;
            sq.serialize_element(&crate::utils::json::BigTableKV {
                name: "geo_mobile_carrier",
                value: self.geo.mobile_carrier_name.as_ref(),
            })?;
            sq.serialize_element(&crate::utils::json::BigTableKV {
                name: "geo_mobile_country",
                value: self.geo.mobile_country.as_ref(),
            })?;
            sq.serialize_element(&crate::utils::json::BigTableKV {
                name: "geo_mobile_mcc",
                value: self.geo.mobile_mcc.as_ref(),
            })?;
            sq.serialize_element(&crate::utils::json::BigTableKV {
                name: "geo_mobile_mnc",
                value: self.geo.mobile_mnc.as_ref(),
            })?;
            sq.serialize_element(&crate::utils::json::BigTableKV {
                name: "container",
                value: self.n,
            })?;
            sq.end()
        }
    }
    map_ser.serialize_entry(
        "proxy",
        &LogProxy {
            p: &proxy,
            geo: &rinfo.rinfo.geoip,
            n: &rinfo.rinfo.container_name,
        },
    )?;

    struct SecurityConfig<'t>(&'t Stats, &'t SecurityPolicy);
    impl<'t> Serialize for SecurityConfig<'t> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut mp = serializer.serialize_map(None)?;
            mp.serialize_entry("revision", &self.0.revision)?;
            mp.serialize_entry("acl_active", &self.0.secpol.acl_enabled)?;
            mp.serialize_entry("cf_active", &self.0.secpol.content_filter_enabled)?;
            mp.serialize_entry("cf_rules", &self.0.content_filter_total)?;
            mp.serialize_entry("rl_rules", &self.0.secpol.limit_amount)?;
            mp.serialize_entry("gf_rules", &self.0.secpol.globalfilters_amount)?;
            mp.serialize_entry("secpolid", &self.1.policy.id)?;
            mp.serialize_entry("secpolentryid", &self.1.entry.id)?;
            mp.end()
        }
    }
    map_ser.serialize_entry("security_config", &SecurityConfig(stats, &rinfo.rinfo.secpolicy))?;

    struct TriggerCounters<'t>(&'t HashMap<InitiatorKind, Vec<&'t BlockReason>>);
    impl<'t> Serialize for TriggerCounters<'t> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let stats_counter = |kd: InitiatorKind| -> usize {
                match self.0.get(&kd) {
                    None => 0,
                    Some(v) => v.len(),
                }
            };
            let acl = stats_counter(InitiatorKind::Acl);
            let global_filters = stats_counter(InitiatorKind::GlobalFilter);
            let rate_limit = stats_counter(InitiatorKind::RateLimit);
            let content_filters = stats_counter(InitiatorKind::ContentFilter);
            let restriction = stats_counter(InitiatorKind::Restriction);

            let mut mp = serializer.serialize_map(None)?;
            mp.serialize_entry("acl", &acl)?;
            mp.serialize_entry("gf", &global_filters)?;
            mp.serialize_entry("rl", &rate_limit)?;
            mp.serialize_entry("cf", &content_filters)?;
            mp.serialize_entry("cf_restrict", &restriction)?;
            mp.end()
        }
    }
    map_ser.serialize_entry("trigger_counters", &TriggerCounters(&greasons))?;

    // blocked (only if doesn't have challenge, because it'll be counted differently)
    if !(has_challenge || has_ichallenge) {
        map_ser.serialize_entry("blocked", &blocked)?;
    }

    struct EmptyMap;
    impl Serialize for EmptyMap {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mp = serializer.serialize_map(Some(0))?;
            mp.end()
        }
    }
    map_ser.serialize_entry("profiling", &stats.timing)?;

    map_ser.serialize_entry("rbz_latency", &stats.timing.max_value())?;

    SerializeMap::end(map_ser)?;
    Ok(outbuffer)
}

//parse and split multiple values into a vector
fn parse_values<T: std::str::FromStr>(val: &str) -> Vec<T> {
    val.split(',')
        .map(|v| v.trim().parse::<T>())
        .filter_map(Result::ok)
        .collect()
}

// blocking version
pub fn jsonlog_block(
    dec: &Decision,
    mrinfo: Option<&RequestInfo>,
    rcode: Option<u32>,
    tags: &Tags,
    stats: &Stats,
    logs: &Logs,
    proxy: HashMap<String, String>,
) -> (Vec<u8>, chrono::DateTime<chrono::Utc>) {
    async_std::task::block_on(jsonlog(dec, mrinfo, rcode, tags, stats, logs, proxy))
}

// an action, as formatted for outside consumption
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Action {
    pub atype: ActionType,
    pub block_mode: bool,
    pub status: u32,
    pub headers: Option<HashMap<String, String>>,
    pub content: String,
    pub extra_tags: Option<HashSet<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SimpleActionT {
    Skip,
    Monitor,
    Custom { content: String },
    Challenge { ch_level: GHMode },
}

impl SimpleActionT {
    fn priority(&self) -> u32 {
        use SimpleActionT::*;
        match self {
            Custom { content: _ } => 8,
            Challenge { ch_level: _ } => 6,
            Monitor => 1,
            Skip => 9,
        }
    }

    pub fn rate_limit_priority(&self) -> u32 {
        use SimpleActionT::*;
        match self {
            Custom { content: _ } => 8,
            Challenge { .. } => 6,
            Monitor => 1,
            // skip action should be ignored when using with rate limit
            Skip => 0,
        }
    }

    fn is_blocking(&self) -> bool {
        !matches!(self, SimpleActionT::Monitor)
    }

    pub fn to_raw(&self) -> RawActionType {
        match self {
            SimpleActionT::Skip => RawActionType::Skip,
            SimpleActionT::Monitor => RawActionType::Monitor,
            SimpleActionT::Custom { .. } => RawActionType::Custom,
            SimpleActionT::Challenge { ch_level } => {
                if ch_level == &GHMode::Active {
                    RawActionType::Challenge
                } else {
                    RawActionType::Ichallenge
                }
            }
        }
    }
}

// an action with its semantic meaning
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimpleAction {
    pub atype: SimpleActionT,
    pub headers: Option<HashMap<String, RequestTemplate>>,
    pub status: u32,
    pub extra_tags: Option<HashSet<String>>,
}

impl Default for SimpleAction {
    fn default() -> Self {
        SimpleAction {
            atype: SimpleActionT::default(),
            headers: None,
            status: 503,
            extra_tags: None,
        }
    }
}

impl Default for SimpleActionT {
    fn default() -> Self {
        SimpleActionT::Custom {
            content: "blocked".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionType {
    Skip,
    Monitor,
    Block,
}

impl ActionType {
    /// is the action blocking (not passed to the underlying server)
    pub fn is_blocking(&self) -> bool {
        matches!(self, ActionType::Block)
    }

    /// is the action final (no further processing)
    pub fn is_final(&self) -> bool {
        !matches!(self, ActionType::Monitor)
    }

    pub fn priority(&self) -> u32 {
        match self {
            ActionType::Block => 6,
            ActionType::Monitor => 1,
            ActionType::Skip => 9,
        }
    }
}

impl std::default::Default for Action {
    fn default() -> Self {
        Action {
            atype: ActionType::Block,
            block_mode: true,
            status: 503,
            headers: None,
            content: "request denied".to_string(),
            extra_tags: None,
        }
    }
}

impl SimpleAction {
    pub fn resolve_actions(logs: &mut Logs, rawactions: Vec<RawAction>) -> HashMap<String, Self> {
        let mut out = HashMap::new();
        for raction in rawactions {
            match Self::resolve(&raction) {
                Ok((id, action)) => {
                    out.insert(id, action);
                }
                Err(r) => logs.error(|| format!("Could not resolve action {}: {}", raction.id, r)),
            }
        }
        out
    }

    fn resolve(rawaction: &RawAction) -> anyhow::Result<(String, SimpleAction)> {
        let id = rawaction.id.clone();
        let atype = match rawaction.type_ {
            RawActionType::Skip => SimpleActionT::Skip,
            RawActionType::Monitor => SimpleActionT::Monitor,
            RawActionType::Custom => SimpleActionT::Custom {
                content: rawaction.params.content.clone().unwrap_or_default(),
            },
            RawActionType::Challenge => SimpleActionT::Challenge {
                ch_level: GHMode::Active,
            },
            RawActionType::Ichallenge => SimpleActionT::Challenge {
                ch_level: GHMode::Interactive,
            },
        };
        let status = rawaction.params.status.unwrap_or(503);
        let headers = rawaction.params.headers.as_ref().map(|hm| {
            hm.iter()
                .map(|(k, v)| (k.to_string(), parse_request_template(v)))
                .collect()
        });
        let extra_tags = if rawaction.tags.is_empty() {
            None
        } else {
            Some(rawaction.tags.iter().cloned().collect())
        };

        Ok((
            id,
            SimpleAction {
                atype,
                status,
                headers,
                extra_tags,
            },
        ))
    }

    /// returns Err(reasons) when it is a challenge, Ok(decision) otherwise
    fn build_decision(
        &self,
        rinfo: &RequestInfo,
        tags: &Tags,
        precision_level: PrecisionLevel,
        reason: Vec<BlockReason>,
    ) -> Result<Decision, Vec<BlockReason>> {
        let mut action = Action::default();
        let mut reason = reason;
        action.block_mode = action.atype.is_blocking();
        action.status = self.status;
        action.headers = self.headers.as_ref().map(|hm| {
            hm.iter()
                .map(|(k, v)| (k.to_string(), render_template(rinfo, tags, v)))
                .collect()
        });
        match &self.atype {
            SimpleActionT::Skip => action.atype = ActionType::Skip,
            SimpleActionT::Monitor => action.atype = ActionType::Monitor,
            SimpleActionT::Custom { content } => {
                action.atype = ActionType::Block;
                action.content = content.clone();
            }
            SimpleActionT::Challenge { ch_level } => {
                let is_human = match ch_level {
                    GHMode::Passive => precision_level.is_human(),
                    GHMode::Active => precision_level.is_human(),
                    GHMode::Interactive => precision_level.is_interactive(),
                };
                if !is_human {
                    return Err(reason);
                }
                action.atype = ActionType::Monitor;
                // clean up challenge reasons
                for r in reason.iter_mut() {
                    r.action.inactive()
                }
            }
        }
        if action.atype == ActionType::Monitor {
            action.status = 200;
            action.block_mode = false;
        }
        Ok(Decision::action(action, reason))
    }

    pub fn to_decision<GH: Grasshopper>(
        &self,
        logs: &mut Logs,
        precision_level: PrecisionLevel,
        mgh: Option<&GH>,
        rinfo: &RequestInfo,
        tags: &mut Tags,
        reason: Vec<BlockReason>,
    ) -> Decision {
        for t in self.extra_tags.iter().flat_map(|s| s.iter()) {
            tags.insert(t, Location::Request);
        }
        if self.atype == SimpleActionT::Skip {
            return Decision {
                maction: None,
                reasons: reason,
            };
        }
        match self.build_decision(rinfo, tags, precision_level, reason) {
            Err(nreason) => match mgh {
                //if None-must be one of the challenge actions
                Some(gh) => {
                    let ch_mode = match &self.atype {
                        SimpleActionT::Challenge { ch_level } => *ch_level,
                        _ => GHMode::Active,
                    };
                    logs.debug(|| format!("Call challenge phase01 with mode: {:?}", ch_mode));
                    challenge_phase01(gh, logs, rinfo, nreason, ch_mode)
                }
                _ => Decision::action(Action::default(), nreason),
            },
            Ok(a) => a,
        }
    }

    pub fn is_blocking(&self) -> bool {
        self.atype.is_blocking()
    }
}

fn render_template(rinfo: &RequestInfo, tags: &Tags, template: &[TemplatePart<TVar>]) -> String {
    let mut out = String::new();
    for p in template {
        match p {
            TemplatePart::Raw(s) => out.push_str(s),
            TemplatePart::Var(TVar::Selector(RequestSelector::Tags)) => {
                out.push_str(&serde_json::to_string(&tags).unwrap_or_else(|_| "null".into()))
            }
            TemplatePart::Var(TVar::Tag(tagname)) => {
                out.push_str(if tags.contains(tagname) { "true" } else { "false" })
            }
            TemplatePart::Var(TVar::Selector(sel)) => match selector(rinfo, sel, Some(tags)) {
                None => out.push_str("nil"),
                Some(Selected::OStr(s)) => out.push_str(&s),
                Some(Selected::Str(s)) => out.push_str(s),
                Some(Selected::U32(v)) => out.push_str(&v.to_string()),
            },
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blocked_no_reasons() {
        let default_action = Some(Action::default());
        let dec = Decision {
            maction: default_action,
            reasons: vec![],
        };
        assert_eq!(dec.blocked(), false);
    }

    #[test]
    fn test_blocked_no_blocking_reasons() {
        let default_action = Some(Action::default());
        let reasons = vec![
            BlockReason::limit(
                "01".to_string(),
                "block-reason-01".to_string(),
                23,
                RawActionType::Monitor,
            ),
            BlockReason::limit("02".to_string(), "block-reason-02".to_string(), 42, RawActionType::Skip),
        ];
        let dec = Decision {
            maction: default_action,
            reasons,
        };
        assert_eq!(dec.blocked(), false);
    }

    #[test]
    fn test_blocked_with_blocking_reason() {
        let default_action = Some(Action::default());
        // phase02 has `RawActionType::Custom`, so should be blocked
        let reasons = vec![
            BlockReason::limit("01".to_string(), "monitor".to_string(), 23, RawActionType::Monitor),
            BlockReason::phase02(),
        ];
        let dec = Decision {
            maction: default_action,
            reasons,
        };
        assert_eq!(dec.blocked(), true);
    }
}
