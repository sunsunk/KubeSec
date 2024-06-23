pub mod acl;
pub mod analyze;
pub mod body;
pub mod config;
pub mod contentfilter;
pub mod flow;
pub mod geo;
pub mod grasshopper;
pub mod incremental;
pub mod interface;
pub mod ipinfo;
pub mod limit;
pub mod logs;
pub mod redis;
pub mod requestfields;
pub mod securitypolicy;
pub mod servergroup;
pub mod simple_executor;
pub mod tagging;
pub mod utils;

use std::collections::HashMap;
use std::sync::Arc;

use analyze::{APhase0, CfRulesArg};
use config::virtualtags::VirtualTags;
use config::with_config;
use grasshopper::{GHQuery, Grasshopper, PrecisionLevel};
use interface::stats::{SecpolStats, Stats, StatsCollect};
use interface::{Action, ActionType, AnalyzeResult, BlockReason, Decision, Location, Tags};
use logs::Logs;
use securitypolicy::match_securitypolicy;
use servergroup::match_servergroup;
use simple_executor::{Executor, Progress, Task};
use tagging::tag_request;
use utils::{map_request, RawRequest, RequestInfo};

use crate::config::custom::Site;
use crate::config::hostmap::SecurityPolicy;
use crate::interface::SimpleAction;
//todo should receive sdk configuration from config/raw.rs struct, and pass it to gg
fn challenge_verified<GH: Grasshopper>(gh: &GH, reqinfo: &RequestInfo, logs: &mut Logs) -> PrecisionLevel {
    match gh.is_human(GHQuery {
        headers: reqinfo.headers.as_map(),
        cookies: reqinfo.cookies.as_map(),
        ip: &reqinfo.rinfo.geoip.ipstr,
        protocol: reqinfo.rinfo.meta.protocol.as_deref().unwrap_or("https"),
    }) {
        Ok(level) => level,
        Err(rr) => {
            logs.error(|| format!("Grasshopper: {}", rr));
            PrecisionLevel::Invalid
        }
    }
}

/// # Safety
///
/// Steps a valid executor
pub unsafe fn inspect_async_step(ptr: *mut Executor<Task<(Decision, Tags, Logs)>>) -> Progress<(Decision, Tags, Logs)> {
    match ptr.as_ref() {
        None => Progress::Error("Null ptr".to_string()),
        Some(r) => r.step(),
    }
}

/// # Safety
///
/// Frees the executor, should be run with the output of executor_init, and only once
pub unsafe fn inspect_async_free(ptr: *mut Executor<(Decision, Tags, Logs)>) {
    if ptr.is_null() {
        return;
    }
    let _x = Box::from_raw(ptr);
}

pub fn inspect_generic_request_map<GH: Grasshopper>(
    mgh: Option<&GH>,
    raw: RawRequest,
    logs: &mut Logs,
    selected_secpol: Option<&str>,
    selected_sergrp: Option<&str>,
    plugins: HashMap<String, String>,
) -> AnalyzeResult {
    async_std::task::block_on(inspect_generic_request_map_async(
        mgh,
        raw,
        logs,
        selected_secpol,
        selected_sergrp,
        plugins,
    ))
}

// generic entry point when the request map has already been parsed
pub fn inspect_generic_request_map_init<GH: Grasshopper>(
    mgh: Option<&GH>,
    raw: RawRequest,
    logs: &mut Logs,
    selected_secpol: Option<&str>,
    selected_sergrp: Option<&str>,
    plugins: HashMap<String, String>,
) -> Result<APhase0, AnalyzeResult> {
    let start = chrono::Utc::now();

    // insert the all tag here, to make sure it is always present, even in the presence of early errors
    let tags = Tags::from_slice(&[(String::from("all"), Location::Request)], VirtualTags::default());

    logs.debug(|| format!("Inspection starts (grasshopper active: {})", mgh.is_some()));

    #[allow(clippy::large_enum_variant)]
    enum RequestMappingResult<A> {
        NoSecurityPolicy,
        BodyTooLarge((SimpleAction, BlockReason), RequestInfo),
        Res(A),
    }

    // do all config queries in the lambda once
    // there is a lot of copying taking place, to minimize the lock time
    // this decision should be backed with benchmarks

    let ((mut ntags, globalfilter_dec, stats), flows, reqinfo, precision_level) =
        match with_config(logs, |slogs, cfg| {
            let mmapinfo = match_securitypolicy(&raw.get_host(), &raw.meta.path, cfg, slogs, selected_secpol);
            let server_group = match_servergroup(cfg, slogs, selected_sergrp);
            match mmapinfo {
                Some(secpolicy) => {
                    // this part is where we use the configuration as much as possible, while we have a lock on it

                    // check if the body is too large
                    // if the body is too large, we store the "too large" action for later use, and set the max depth to 0
                    let body_too_large = if let Some(body) = raw.mbody {
                        if body.len() > secpolicy.content_filter_profile.max_body_size
                            && !secpolicy.content_filter_profile.ignore_body
                        {
                            Some((
                                secpolicy.content_filter_profile.action.clone(),
                                BlockReason::body_too_large(
                                    secpolicy.content_filter_profile.id.clone(),
                                    secpolicy.content_filter_profile.name.clone(),
                                    secpolicy.content_filter_profile.action.atype.to_raw(),
                                    body.len(),
                                    secpolicy.content_filter_profile.max_body_size,
                                ),
                            ))
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                    let stats = StatsCollect::new(slogs.start, cfg.revision.clone())
                        .secpol(SecpolStats::build(&secpolicy, cfg.globalfilters.len()));

                    // if the max depth is equal to 0, the body will not be parsed
                    let reqinfo = map_request(
                        slogs,
                        secpolicy,
                        server_group,
                        cfg.container_name.clone(),
                        &raw,
                        Some(start),
                        plugins.clone(),
                    );

                    if let Some(action) = body_too_large {
                        return RequestMappingResult::BodyTooLarge(action, reqinfo);
                    }

                    let nflows = cfg.flows.clone();

                    // without grasshopper, default to being not human
                    let precision_level = if let Some(gh) = mgh {
                        challenge_verified(gh, &reqinfo, slogs)
                    } else {
                        PrecisionLevel::Invalid
                    };

                    let ntags = tag_request(stats, precision_level, &cfg.globalfilters, &reqinfo, &cfg.virtual_tags);
                    RequestMappingResult::Res((ntags, nflows, reqinfo, precision_level))
                }
                None => RequestMappingResult::NoSecurityPolicy,
            }
        }) {
            Some(RequestMappingResult::Res(x)) => x,
            Some(RequestMappingResult::BodyTooLarge((action, br), rinfo)) => {
                let mut tags = tags;
                let decision = action.to_decision(logs, PrecisionLevel::Invalid, mgh, &rinfo, &mut tags, vec![br]);
                return Err(AnalyzeResult {
                    decision,
                    tags,
                    rinfo,
                    stats: Stats::new(logs.start, "unknown".into()),
                });
            }
            Some(RequestMappingResult::NoSecurityPolicy) => {
                logs.debug("No security policy found");
                let mut secpol = SecurityPolicy::default();
                secpol.content_filter_profile.ignore_body = true;
                let server_group = Site::default();
                let rinfo = map_request(
                    logs,
                    Arc::new(secpol),
                    Arc::new(server_group),
                    None,
                    &raw,
                    Some(start),
                    plugins,
                );
                return Err(AnalyzeResult {
                    decision: Decision::pass(Vec::new()),
                    tags,
                    rinfo,
                    stats: Stats::new(logs.start, "unknown".into()),
                });
            }
            None => {
                logs.debug("Something went wrong during security policy searching");
                let mut secpol = SecurityPolicy::default();
                secpol.content_filter_profile.ignore_body = true;
                let server_group = Site::default();
                let rinfo = map_request(
                    logs,
                    Arc::new(secpol),
                    Arc::new(server_group),
                    None,
                    &raw,
                    Some(start),
                    plugins,
                );
                return Err(AnalyzeResult {
                    decision: Decision::pass(Vec::new()),
                    tags,
                    rinfo,
                    stats: Stats::new(logs.start, "unknown".into()),
                });
            }
        };
    ntags.extend(tags);

    Ok(APhase0 {
        stats,
        itags: ntags,
        reqinfo,
        precision_level,
        globalfilter_dec,
        flows,
    })
}

// generic entry point when the request map has already been parsed
pub async fn inspect_generic_request_map_async<GH: Grasshopper>(
    mgh: Option<&GH>,
    raw: RawRequest<'_>,
    logs: &mut Logs,
    selected_secpol: Option<&str>,
    selected_sergrp: Option<&str>,
    plugins: HashMap<String, String>,
) -> AnalyzeResult {
    match inspect_generic_request_map_init(mgh, raw, logs, selected_secpol, selected_sergrp, plugins) {
        Err(res) => res,
        Ok(p0) => analyze::analyze(logs, mgh, p0, CfRulesArg::Global).await,
    }
}
