use crate::config::raw::AclProfile;
use crate::interface::{AclStage, Tags};

use std::collections::HashSet;

#[derive(Debug, Clone)]
pub struct AclDecisionDetails {
    pub stage: AclStage,
    pub tags: Tags,
    pub challenge: bool,
}

#[derive(Debug)]
pub enum AclResult {
    /// passthrough found
    Passthrough((bool, Tags)),
    /// bots, human results
    Match {
        bot: Option<(bool, Tags)>,
        human: Option<(bool, Tags)>,
    },
}

impl std::fmt::Display for AclResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let pair = |f: &mut std::fmt::Formatter, m: Option<&(bool, Tags)>| -> std::fmt::Result {
            match m {
                Some((allowed, tags)) => {
                    if *allowed {
                        write!(f, "(allowed {})", tags)
                    } else {
                        write!(f, "(denied {})", tags)
                    }
                }
                None => "(none)".fmt(f),
            }
        };
        match self {
            AclResult::Passthrough(pr) => {
                "passthrough".fmt(f)?;
                pair(f, Some(pr))
            }
            AclResult::Match { bot, human } => {
                "bot".fmt(f)?;
                pair(f, bot.as_ref())?;
                "/human".fmt(f)?;
                pair(f, human.as_ref())
            }
        }
    }
}

pub fn check_acl(tags: &Tags, acl: &AclProfile) -> AclResult {
    let subcheck = |checks: &HashSet<String>, allowed: bool| {
        let tags = tags.intersect_tags(checks);
        if tags.is_empty() {
            None
        } else {
            Some((allowed, tags))
        }
    };
    subcheck(&acl.force_deny, false)
        .map(AclResult::Passthrough)
        .or_else(|| subcheck(&acl.passthrough, true).map(AclResult::Passthrough))
        .unwrap_or_else(|| {
            let botresult = subcheck(&acl.allow_bot, true).or_else(|| subcheck(&acl.deny_bot, false));
            let humanresult = subcheck(&acl.allow, true).or_else(|| subcheck(&acl.deny, false));

            AclResult::Match {
                bot: botresult,
                human: humanresult,
            }
        })
}

impl AclResult {
    pub fn has_matched(&self) -> bool {
        match self {
            AclResult::Passthrough(_) => true,
            AclResult::Match { bot, human } => bot.is_some() || human.is_some(),
        }
    }

    pub fn decision(self, is_human: bool) -> Option<AclDecisionDetails> {
        match self {
            AclResult::Passthrough((allowed, tags)) => Some(AclDecisionDetails {
                stage: if allowed {
                    AclStage::Bypass
                } else {
                    AclStage::EnforceDeny
                },
                tags,
                challenge: false,
            }),
            AclResult::Match { bot: None, human: None } => None,
            AclResult::Match {
                bot: Some((true, _)),
                human: Some((false, tags)),
            } => Some(AclDecisionDetails {
                stage: AclStage::Deny,
                tags,
                challenge: false,
            }),
            AclResult::Match {
                bot: Some((true, tags)),
                human: _,
            } => Some(AclDecisionDetails {
                stage: AclStage::AllowBot,
                tags,
                challenge: false,
            }),
            AclResult::Match {
                bot: Some((false, tags)),
                human: Some((false, _)),
            } if !is_human => Some(AclDecisionDetails {
                stage: AclStage::DenyBot,
                tags,
                challenge: false,
            }),
            AclResult::Match {
                bot: Some((false, tags)),
                human: _,
            } if !is_human => Some(AclDecisionDetails {
                stage: AclStage::DenyBot,
                tags,
                challenge: true,
            }),
            AclResult::Match {
                bot: _,
                human: Some((allowed, tags)),
            } => Some(AclDecisionDetails {
                stage: if allowed { AclStage::Allow } else { AclStage::Deny },
                tags,
                challenge: false,
            }),
            _ => None,
        }
    }
}
