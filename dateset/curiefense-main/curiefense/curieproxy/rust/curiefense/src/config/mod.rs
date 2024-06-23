pub mod contentfilter;
pub mod custom;
pub mod flow;
pub mod globalfilter;
pub mod hostmap;
pub mod limit;
pub mod matchers;
pub mod raw;
pub mod virtualtags;

use lazy_static::lazy_static;
use std::collections::HashMap;
use std::collections::HashSet;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::RwLock;

use crate::config::limit::Limit;
use crate::interface::SimpleAction;
use crate::logs::Logs;
use contentfilter::{resolve_rules, ContentFilterProfile, ContentFilterRules};
use custom::Site;
use flow::flow_resolve;
use globalfilter::GlobalFilterSection;
use hostmap::{HostMap, PolicyId, SecurityPolicy};
use jsonpath_rust::JsonPathFinder;
use matchers::Matching;
use raw::{
    AclProfile, RawFlowEntry, RawGlobalFilterSection, RawHostMap, RawLimit, RawSecurityPolicy, RawSite, RawVirtualTag,
};
use virtualtags::{vtags_resolve, VirtualTags};

use self::flow::FlowMap;
use self::matchers::RequestSelector;
use self::raw::RawAclProfile;
use self::raw::RawManifest;

static ALL_CONFIG_FILES: [&str; 11] = [
    "actions.json",
    "acl-profiles.json",
    "contentfilter-profiles.json",
    "contentfilter-rules.json",
    "globalfilter-lists.json",
    "limits.json",
    "manifest.json",
    "securitypolicy.json",
    "flow-control.json",
    "virtual-tags.json",
    "custom.json",
];

pub struct LockedConfig {
    pub config: RwLock<Config>,
    pub hsdb: RwLock<HashMap<String, ContentFilterRules>>,
}

impl LockedConfig {
    fn initial() -> Self {
        let mut config = Config::load(Logs::default(), "/cf-config/current/config");
        let path = Path::new("/cf-config/current/config/json");
        let hsdb = load_hsdb(&mut config.logs, path, &config.content_filter_profiles);
        LockedConfig {
            config: RwLock::new(config),
            hsdb: RwLock::new(hsdb),
        }
    }
}

lazy_static! {
    pub static ref CONFIGS: LockedConfig = LockedConfig::initial();
    static ref CONFIG_DEPENDENCIES: HashMap<&'static str, Vec<String>> = {
        let mut map = HashMap::new();

        map.insert(
            "actions.json",
            vec![
                "acl-profiles.json".to_string(),
                "contentfilter-profiles.json".to_string(),
                "contentfilter-rules.json".to_string(),
                "globalfilter-lists.json".to_string(),
                "limits.json".to_string(),
                "securitypolicy.json".to_string(),
                "manifest.json".to_string(),
            ],
        );
        map.insert(
            "contentfilter-profiles.json",
            vec![
                "contentfilter-rules.json".to_string(),
                "securitypolicy.json".to_string(),
                "manifest.json".to_string(),
            ],
        );
        map.insert(
            "limits.json",
            vec!["securitypolicy.json".to_string(), "manifest.json".to_string()],
        );
        map.insert(
            "acl-profiles.json",
            vec!["securitypolicy.json".to_string(), "manifest.json".to_string()],
        );

        // add generic dependency to the manifest
        for f in ALL_CONFIG_FILES {
            if !map.contains_key(f) && f != "manifest.json" {
                map.insert(f, vec!["manifest.json".to_string()]);
            }
        }

        map
    };
}

fn container_name() -> Option<String> {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_string())
}

fn config_logs(cur: &mut Logs, cfg: &Config) {
    cur.debug("CFGLOAD logs start");
    cur.extend(cfg.logs.clone());
    cur.debug("CFGLOAD logs end");
}

pub fn with_config<R, F>(logs: &mut Logs, f: F) -> Option<R>
where
    F: FnOnce(&mut Logs, &Config) -> R,
{
    match CONFIGS.config.read() {
        Ok(cfg) => {
            config_logs(logs, &cfg);
            Some(f(logs, &cfg))
        }
        Err(rr) =>
        // read failed :(
        {
            logs.error(|| rr.to_string());
            None
        }
    }
}

pub fn reload_config(basepath: &str, filenames: Vec<String>) {
    let mut logs = Logs::default();

    let mut bjson = PathBuf::from(basepath);
    bjson.push("json");

    let mut files_to_reload = HashSet::new();
    if filenames.is_empty() {
        // if filename was not provided, reload all config files
        files_to_reload.extend(ALL_CONFIG_FILES.iter().map(|s| s.to_string()));
    } else {
        for filename in filenames.iter() {
            if let Some(deps) = CONFIG_DEPENDENCIES.get(filename.as_str()) {
                files_to_reload.extend(deps.clone());
            }
        }
        files_to_reload.extend(filenames);
    }

    let mut config = match CONFIGS.config.read() {
        Ok(cfg) => cfg.clone(),
        Err(rr) => {
            logs.error(|| rr.to_string());
            return;
        }
    };
    let mut hsdb: Option<_> = None;

    if files_to_reload.contains("manifest.json") {
        let mmanifest: Result<RawManifest, String> = PathBuf::from(basepath)
            .parent()
            .ok_or_else(|| "could not get parent directory?".to_string())
            .and_then(|x| {
                let mut pth = x.to_owned();
                pth.push("manifest.json");
                std::fs::File::open(pth).map_err(|rr| rr.to_string())
            })
            .and_then(|file| serde_json::from_reader(file).map_err(|rr| rr.to_string()));

        let revision = match mmanifest {
            Err(rr) => {
                logs.error(move || format!("When loading manifest.json: {}", rr));
                "unknown".to_string()
            }
            Ok(manifest) => manifest.meta.version,
        };
        config.revision = revision;
    }
    if files_to_reload.contains("actions.json") {
        let rawactions = Config::load_config_file(&mut logs, &bjson, "actions.json");
        let actions = SimpleAction::resolve_actions(&mut logs, rawactions);
        config.actions = actions;
    }
    if files_to_reload.contains("acl-profiles.json") {
        let raw_acls: Vec<RawAclProfile> = Config::load_config_file(&mut logs, &bjson, "acl-profiles.json");
        let acls = raw_acls
            .into_iter()
            .map(|a| (a.id.clone(), AclProfile::resolve(&mut logs, &config.actions, a)))
            .collect();
        config.acls = acls;
    }
    if files_to_reload.contains("contentfilter-profiles.json") {
        let raw_content_filter_profiles = Config::load_config_file(&mut logs, &bjson, "contentfilter-profiles.json");
        let content_filter_profiles =
            ContentFilterProfile::resolve(&mut logs, &config.actions, raw_content_filter_profiles);
        config.content_filter_profiles = content_filter_profiles;
    }
    if files_to_reload.contains("contentfilter-rules.json") {
        hsdb = Some(load_hsdb(&mut logs, &bjson, &config.content_filter_profiles));
    }
    if files_to_reload.contains("globalfilter-lists.json") {
        let raw_global_filters = Config::load_config_file(&mut logs, &bjson, "globalfilter-lists.json");
        let globalfilters = GlobalFilterSection::resolve(&mut logs, &config.actions, raw_global_filters);
        config.globalfilters = globalfilters;
    }
    if files_to_reload.contains("limits.json") {
        let raw_limits = Config::load_config_file(&mut logs, &bjson, "limits.json");
        let (limits, global_limits, inactive_limits) = Limit::resolve(&mut logs, &config.actions, raw_limits);
        config.limits = limits;
        config.global_limits = global_limits;
        config.inactive_limits = inactive_limits;
    }
    if files_to_reload.contains("securitypolicy.json") {
        let raw_sec_pol = Config::load_config_file(&mut logs, &bjson, "securitypolicy.json");
        let (securitypolicies_map, securitypolicies, default) = sec_pol_resolve(
            &mut logs,
            raw_sec_pol,
            &config.limits,
            &config.global_limits,
            &config.inactive_limits,
            &config.acls,
            &config.content_filter_profiles,
        );
        config.securitypolicies_map = securitypolicies_map;
        config.securitypolicies = securitypolicies;
        config.default = default;
    }
    if files_to_reload.contains("flow-control.json") {
        let raw_flows = Config::load_config_file(&mut logs, &bjson, "flow-control.json");
        let flows = flow_resolve(&mut logs, raw_flows);
        config.flows = flows;
    }
    if files_to_reload.contains("virtual-tags.json") {
        let raw_virtual_tags = Config::load_config_file(&mut logs, &bjson, "virtual-tags.json");
        let virtual_tags = vtags_resolve(&mut logs, raw_virtual_tags);
        config.virtual_tags = virtual_tags;
    }
    if files_to_reload.contains("custom.json") {
        let (rawsites,) = Config::load_custom_config_file(&mut logs, &bjson, "custom.json");
        let servergroups_map = Site::resolve(&mut logs, rawsites);
        config.servergroups_map = servergroups_map;
    }

    config.logs = logs.clone();

    match CONFIGS.config.write() {
        Ok(mut w) => *w = config,
        Err(rr) => logs.error(|| rr.to_string()),
    };
    if let Some(hsdb) = hsdb {
        match CONFIGS.hsdb.write() {
            Ok(mut dbw) => *dbw = hsdb,
            Err(rr) => logs.error(|| rr.to_string()),
        };
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub revision: String,
    pub securitypolicies_map: HashMap<String, HostMap>, // used when the security policy is set
    pub securitypolicies: Vec<Matching<HostMap>>,
    pub globalfilters: Vec<GlobalFilterSection>,
    pub default: Option<HostMap>,
    pub container_name: Option<String>,
    pub flows: FlowMap,
    pub content_filter_profiles: HashMap<String, ContentFilterProfile>,
    pub virtual_tags: VirtualTags,
    pub logs: Logs,
    pub servergroups_map: HashMap<String, Site>,

    // Not used when processing request, but to optimize reloading config
    pub actions: HashMap<String, SimpleAction>,
    pub limits: HashMap<String, Limit>,
    pub global_limits: Vec<Limit>,
    pub inactive_limits: HashSet<String>,
    pub acls: HashMap<String, AclProfile>,
}

fn from_map<V: Clone>(mp: &HashMap<String, V>, k: &str) -> Result<V, String> {
    mp.get(k).cloned().ok_or_else(|| {
        let all_keys: String = mp.keys().map(|s| s.as_str()).collect::<Vec<&str>>().join(",");
        format!("id not found: {}, all ids are: {}", k, all_keys)
    })
}

#[allow(clippy::too_many_arguments)]
impl Config {
    fn resolve_security_policies(
        logs: &mut Logs,
        policyid: &str,
        policyname: &str,
        rawmaps: Vec<RawSecurityPolicy>,
        tags: Vec<String>,
        limits: &HashMap<String, Limit>,
        global_limits: &[Limit],
        inactive_limits: &HashSet<String>,
        acls: &HashMap<String, AclProfile>,
        contentfilterprofiles: &HashMap<String, ContentFilterProfile>,
        session: Vec<RequestSelector>,
        session_ids: Vec<RequestSelector>,
    ) -> (Vec<Matching<Arc<SecurityPolicy>>>, Option<Arc<SecurityPolicy>>) {
        let mut default: Option<Arc<SecurityPolicy>> = None;
        let mut entries: Vec<Matching<Arc<SecurityPolicy>>> = Vec::new();
        for rawmap in rawmaps {
            let mapname = rawmap.name.clone();
            let acl_profile: AclProfile = match acls.get(&rawmap.acl_profile) {
                Some(p) => p.clone(),
                None => {
                    logs.warning(|| format!("Unknown ACL profile {}", &rawmap.acl_profile));
                    AclProfile::default()
                }
            };
            let content_filter_profile: ContentFilterProfile =
                match contentfilterprofiles.get(&rawmap.content_filter_profile) {
                    Some(p) => p.clone(),
                    None => {
                        logs.error(|| format!("Unknown Content Filter profile {}", &rawmap.content_filter_profile));
                        continue;
                    }
                };
            let mut olimits: Vec<Limit> = Vec::new();
            for gl in global_limits {
                if !rawmap.limit_ids.contains(&gl.id) {
                    olimits.push(gl.clone());
                }
            }
            for lid in rawmap.limit_ids {
                if !inactive_limits.contains(&lid) {
                    match from_map(limits, &lid) {
                        Ok(lm) => olimits.push(lm),
                        Err(rr) => logs.error(|| format!("When resolving limits in rawmap {}, {}", mapname, rr)),
                    }
                } else {
                    logs.debug(|| format!("Trying to add inactive limit {} in map {}", lid, mapname))
                }
            }
            let securitypolicy = SecurityPolicy {
                policy: PolicyId {
                    id: policyid.to_string(),
                    name: policyname.to_string(),
                },
                entry: PolicyId {
                    id: rawmap.id.unwrap_or_else(|| mapname.clone()),
                    name: rawmap.name,
                },
                tags: tags.clone(),
                session: session.clone(),
                session_ids: session_ids.clone(),
                acl_active: rawmap.acl_active,
                acl_profile,
                content_filter_active: rawmap.content_filter_active,
                content_filter_profile,
                limits: olimits,
            };
            if rawmap.match_ == "__default__"
                || securitypolicy.entry.id == "__default__"
                || (rawmap.match_ == "/"
                    && (securitypolicy.entry.id == "default"
                        || securitypolicy.entry.name == "default"
                        || securitypolicy.entry.name == "__default__"))
            {
                if default.is_some() {
                    logs.warning("Multiple __default__ maps");
                }
                default = Some(Arc::new(securitypolicy));
            } else {
                match Matching::from_str(&rawmap.match_, Arc::new(securitypolicy)) {
                    Err(rr) => {
                        logs.warning(format!("Invalid regex {} in entry {}: {}", &rawmap.match_, &mapname, rr).as_str())
                    }
                    Ok(matcher) => entries.push(matcher),
                }
            }
        }
        entries.sort_by_key(|x: &Matching<Arc<SecurityPolicy>>| usize::MAX - x.matcher_len());
        (entries, default)
    }

    fn resolve(
        logs: Logs,
        revision: String,
        actions: HashMap<String, SimpleAction>,
        rawmaps: Vec<RawHostMap>,
        rawlimits: Vec<RawLimit>,
        rawglobalfilters: Vec<RawGlobalFilterSection>,
        rawacls: Vec<RawAclProfile>,
        content_filter_profiles: HashMap<String, ContentFilterProfile>,
        container_name: Option<String>,
        rawflows: Vec<RawFlowEntry>,
        rawvirtualtags: Vec<RawVirtualTag>,
        rawsites: Vec<RawSite>,
    ) -> Config {
        let mut logs = logs;

        let (limits, global_limits, inactive_limits) = Limit::resolve(&mut logs, &actions, rawlimits);
        let acls = rawacls
            .into_iter()
            .map(|a| (a.id.clone(), AclProfile::resolve(&mut logs, &actions, a)))
            .collect();

        let (securitypolicies_map, securitypolicies, default) = sec_pol_resolve(
            &mut logs,
            rawmaps,
            &limits,
            &global_limits,
            &inactive_limits,
            &acls,
            &content_filter_profiles,
        );

        let globalfilters = GlobalFilterSection::resolve(&mut logs, &actions, rawglobalfilters);

        let flows = flow_resolve(&mut logs, rawflows);

        let virtual_tags = vtags_resolve(&mut logs, rawvirtualtags);

        let servergroups_map = Site::resolve(&mut logs, rawsites);

        Config {
            revision,
            securitypolicies_map,
            securitypolicies,
            globalfilters,
            default,
            container_name,
            flows,
            content_filter_profiles,
            logs,
            virtual_tags,
            actions,
            limits,
            global_limits,
            inactive_limits,
            acls,
            servergroups_map,
        }
    }

    //custom.json is built differently, use this function to extract needed data.
    //right now it returns only sites data, can be extended if needed
    fn load_custom_config_file(logs: &mut Logs, base: &Path, fname: &str) -> (Vec<RawSite>,) {
        let mut path = base.to_path_buf();
        path.push(fname);
        let fullpath = path.to_str().unwrap_or(fname).to_string();
        let file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(rr) => {
                logs.error(|| format!("when loading {}: {}", fullpath, rr));
                return (Vec::new(),);
            }
        };

        let file_content_res = std::fs::read_to_string(fullpath).ok().map(|s| s.trim().to_string());
        let file_content = match file_content_res {
            Some(content) => content,
            None => "{}".to_string(),
        };

        // JSONPath expression to match the element with id 'sites'
        let json_path = "$[?(@.id == 'sites')].items.*";

        let mut sites_vec: Vec<RawSite> = Vec::new();
        match JsonPathFinder::from_str(&file_content, json_path) {
            Ok(finder) => {
                let found_sites = finder.find();

                if let serde_json::Value::Array(arr) = found_sites {
                    for site in arr {
                        if let serde_json::Value::Object(site_object) = site {
                            if let Ok(site_struct) =
                                serde_json::from_value::<RawSite>(serde_json::Value::Object(site_object))
                            {
                                sites_vec.push(site_struct);
                            }
                        }
                    }
                }
            }
            Err(e) => {
                logs.error(|| format!("when applying JSONPath expression: err: {:?}", e));
            }
        };

        (sites_vec,)
    }

    fn load_config_file<A: serde::de::DeserializeOwned>(logs: &mut Logs, base: &Path, fname: &str) -> Vec<A> {
        let mut path = base.to_path_buf();
        path.push(fname);
        let fullpath = path.to_str().unwrap_or(fname).to_string();
        let file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(rr) => {
                logs.error(|| format!("when loading {}: {}", fullpath, rr));
                return Vec::new();
            }
        };
        let values: Vec<serde_json::Value> = match serde_json::from_reader(std::io::BufReader::new(file)) {
            Ok(vs) => vs,
            Err(rr) => {
                // if it is not a json array, abort early and do not resolve anything
                logs.error(|| format!("when parsing {}: {}", fullpath, rr));
                return Vec::new();
            }
        };
        let mut out = Vec::new();
        for value in values {
            // for each entry, try to resolve it as a raw configuration value, failing otherwise
            match serde_json::from_value(value) {
                Err(rr) => {
                    logs.error(|| format!("when resolving entry from {}: {}", fullpath, rr));
                }
                Ok(v) => out.push(v),
            }
        }
        out
    }

    fn load(mut logs: Logs, basepath: &str) -> Config {
        let mut bjson = PathBuf::from(basepath);
        bjson.push("json");

        logs.debug(|| format!("Loading configuration from {}", basepath));

        let mmanifest: Result<RawManifest, String> = PathBuf::from(basepath)
            .parent()
            .ok_or_else(|| "could not get parent directory?".to_string())
            .and_then(|x| {
                let mut pth = x.to_owned();
                pth.push("manifest.json");
                std::fs::File::open(pth).map_err(|rr| rr.to_string())
            })
            .and_then(|file| serde_json::from_reader(file).map_err(|rr| rr.to_string()));

        let revision = match mmanifest {
            Err(rr) => {
                logs.error(move || format!("When loading manifest.json: {}", rr));
                "unknown".to_string()
            }
            Ok(manifest) => manifest.meta.version,
        };

        let rawactions = Config::load_config_file(&mut logs, &bjson, "actions.json");
        let securitypolicy = Config::load_config_file(&mut logs, &bjson, "securitypolicy.json");
        let globalfilters = Config::load_config_file(&mut logs, &bjson, "globalfilter-lists.json");
        let limits = Config::load_config_file(&mut logs, &bjson, "limits.json");
        let acls = Config::load_config_file(&mut logs, &bjson, "acl-profiles.json");
        let rawcontentfilterprofiles = Config::load_config_file(&mut logs, &bjson, "contentfilter-profiles.json");
        let flows = Config::load_config_file(&mut logs, &bjson, "flow-control.json");
        let virtualtags = Config::load_config_file(&mut logs, &bjson, "virtual-tags.json");
        // let rawsites: Vec<RawSite> = Config::load_custom_config_file(&mut logs, &bjson, "custom.json");
        let (rawsites,) = Config::load_custom_config_file(&mut logs, &bjson, "custom.json");

        let container_name = container_name();

        let actions = SimpleAction::resolve_actions(&mut logs, rawactions);
        let content_filter_profiles = ContentFilterProfile::resolve(&mut logs, &actions, rawcontentfilterprofiles);

        Config::resolve(
            logs,
            revision,
            actions,
            securitypolicy,
            limits,
            globalfilters,
            acls,
            content_filter_profiles,
            container_name,
            flows,
            virtualtags,
            rawsites,
        )
    }

    pub fn empty() -> Config {
        Config {
            revision: "dummy".to_string(),
            securitypolicies_map: HashMap::new(),
            securitypolicies: Vec::new(),
            globalfilters: Vec::new(),
            default: None,
            container_name: container_name(),
            flows: HashMap::new(),
            content_filter_profiles: HashMap::new(),
            logs: Logs::default(),
            virtual_tags: Arc::new(HashMap::new()),
            actions: HashMap::new(),
            limits: HashMap::new(),
            global_limits: Vec::new(),
            inactive_limits: HashSet::new(),
            acls: HashMap::new(),
            servergroups_map: HashMap::new(),
        }
    }
}

pub fn load_hsdb(
    logs: &mut Logs,
    configpath: &Path,
    profiles: &HashMap<String, ContentFilterProfile>,
) -> HashMap<String, ContentFilterRules> {
    let rawcontentfilterrules = Config::load_config_file(logs, configpath, "contentfilter-rules.json");
    let contentfilterrules = rawcontentfilterrules
        .into_iter()
        .filter_map(|r| {
            contentfilter::convert_rule(r)
                .map_err(|rr| logs.error(|| rr.to_string()))
                .ok()
        })
        .collect();
    resolve_rules(logs, profiles, contentfilterrules)
}

// securitypolicies_map, securitypolicies, default
fn sec_pol_resolve(
    logs: &mut Logs,
    rawmaps: Vec<RawHostMap>,
    limits: &HashMap<String, Limit>,
    global_limits: &[Limit],
    inactive_limits: &HashSet<String>,
    acls: &HashMap<String, AclProfile>,
    content_filter_profiles: &HashMap<String, ContentFilterProfile>,
) -> (HashMap<String, HostMap>, Vec<Matching<HostMap>>, Option<HostMap>) {
    let mut default: Option<HostMap> = None;
    let mut securitypolicies: Vec<Matching<HostMap>> = Vec::new();
    let mut securitypolicies_map = HashMap::new();
    // build the entries while looking for the default entry
    for rawmap in rawmaps {
        let mapname = rawmap.name.clone();
        let msession: anyhow::Result<Vec<RequestSelector>> = if rawmap.session.is_empty() {
            Ok(Vec::new())
        } else {
            rawmap
                .session
                .into_iter()
                .map(RequestSelector::resolve_selector_map)
                .collect()
        };
        let msession_ids: anyhow::Result<Vec<RequestSelector>> = rawmap
            .session_ids
            .into_iter()
            .map(RequestSelector::resolve_selector_map)
            .collect();
        let session = msession.unwrap_or_else(|rr| {
            logs.error(|| format!("error when decoding session in {}, {}", &mapname, rr));
            Vec::new()
        });

        let session_ids = msession_ids.unwrap_or_else(|rr| {
            logs.error(|| format!("error when decoding session_ids in {}, {}", &mapname, rr));
            Vec::new()
        });
        let (entries, default_entry) = Config::resolve_security_policies(
            logs,
            &rawmap.id,
            &rawmap.name,
            rawmap.map,
            rawmap.tags,
            limits,
            global_limits,
            inactive_limits,
            acls,
            content_filter_profiles,
            session,
            session_ids,
        );
        if default_entry.is_none() {
            logs.warning(format!("HostMap entry '{}' does not have a default entry", &rawmap.name).as_str());
        }
        let hostmap = HostMap {
            name: rawmap.name,
            entries,
            default: default_entry,
        };
        securitypolicies_map.insert(rawmap.id, hostmap.clone());
        if rawmap.match_ == "__default__" {
            if default.is_some() {
                logs.error(|| format!("HostMap entry '{}' has several default entries", hostmap.name));
            }
            default = Some(hostmap);
        } else {
            match Matching::from_str(&rawmap.match_, hostmap) {
                Err(rr) => {
                    logs.error(format!("Invalid regex {} in entry {}: {}", &rawmap.match_, mapname, rr).as_str())
                }
                Ok(matcher) => securitypolicies.push(matcher),
            }
        }
    }

    // order by decreasing matcher length, so that more specific rules are matched first
    securitypolicies.sort_by_key(|b| std::cmp::Reverse(b.matcher_len()));

    (securitypolicies_map, securitypolicies, default)
}
