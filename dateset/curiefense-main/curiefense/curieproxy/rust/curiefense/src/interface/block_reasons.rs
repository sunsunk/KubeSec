/// this file contains all the data type that are used when interfacing with a proxy
use crate::config::{contentfilter::SectionIdx, raw::RawActionType};
use serde::ser::SerializeMap;
use serde::Serialize;
use serde_json::Value;
use std::collections::{HashMap, HashSet};

use super::tagging::{Location, Tags};

#[derive(Debug, Clone, Copy, Serialize, Hash, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AclStage {
    EnforceDeny,
    Bypass,
    AllowBot,
    DenyBot,
    Allow,
    Deny,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum Initiator {
    GlobalFilter,
    Acl {
        tags: Vec<String>,
        stage: AclStage,
    },
    ContentFilter {
        ruleid: String,
        risk_level: u8,
    },
    Limit {
        threshold: u64,
    },
    Restriction {
        tpe: &'static str,
        actual: String,
        expected: String,
    },

    // TODO, these two are not serialized for now
    Phase01Fail(String),
    Phase02,
}

impl std::fmt::Display for Initiator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use Initiator::*;
        match self {
            GlobalFilter => write!(f, "global filter"),
            Acl { tags, stage } => write!(f, "acl {:?} {:?}", stage, tags),
            ContentFilter { ruleid, risk_level } => write!(f, "content filter {}[lvl{}]", ruleid, risk_level),
            Limit { threshold } => write!(f, "rate limit threshold={}", threshold),
            Phase01Fail(r) => write!(f, "grasshopper phase 1 error: {}", r),
            Phase02 => write!(f, "grasshopper phase 2"),
            Restriction { tpe, actual, expected } => write!(f, "restricted {}[{}/{}]", tpe, actual, expected),
        }
    }
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InitiatorKind {
    Acl,
    RateLimit,
    GlobalFilter,
    ContentFilter,
    Restriction,
}

impl Initiator {
    pub fn to_kind(&self) -> Option<InitiatorKind> {
        use InitiatorKind::*;
        match self {
            Initiator::GlobalFilter { .. } => Some(GlobalFilter),
            Initiator::Acl { .. } => Some(Acl),
            Initiator::ContentFilter { .. } => Some(ContentFilter),
            Initiator::Limit { .. } => Some(RateLimit),
            Initiator::Phase01Fail(_) => None,
            Initiator::Phase02 => None,
            Initiator::Restriction { .. } => Some(Restriction),
        }
    }

    pub fn serialize_in_map<S: serde::Serializer>(
        &self,
        map: &mut <S as serde::Serializer>::SerializeMap,
    ) -> Result<(), S::Error> {
        match self {
            Initiator::GlobalFilter => (),
            Initiator::Acl { tags, stage } => {
                map.serialize_entry("tags", tags)?;
                map.serialize_entry("acl_action", stage)?;
            }
            Initiator::ContentFilter { ruleid, risk_level } => {
                map.serialize_entry("ruleid", ruleid)?;
                map.serialize_entry("risk_level", risk_level)?;
            }
            Initiator::Limit { threshold } => {
                map.serialize_entry("threshold", threshold)?;
            }
            Initiator::Restriction { tpe, actual, expected } => {
                map.serialize_entry("type", tpe)?;
                map.serialize_entry("actual", actual)?;
                map.serialize_entry("expected", expected)?;
            }

            // not serialized
            Initiator::Phase01Fail(r) => {
                map.serialize_entry("type", "phase1")?;
                map.serialize_entry("details", r)?;
            }
            Initiator::Phase02 => {
                map.serialize_entry("type", "phase2")?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockReason {
    pub id: String,
    pub name: String,
    pub initiator: Initiator,
    pub location: Location,
    pub extra_locations: Vec<Location>,
    pub action: RawActionType,
    pub extra: Value,
}

impl Serialize for BlockReason {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map: <S as serde::Serializer>::SerializeMap = serializer.serialize_map(None)?;
        self.serialize_in_map::<S>(&mut map)?;
        map.end()
    }
}

impl std::fmt::Display for BlockReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:?} - {} - {} - [{}]",
            self.action, self.initiator, self.name, self.location
        )
    }
}

fn extra_locations<'t, I: Iterator<Item = &'t Location>>(i: I) -> (Location, Vec<Location>) {
    let mut liter = i.cloned();
    let location = liter.next().unwrap_or(Location::Request);
    let extra = liter.collect();
    (location, extra)
}

impl BlockReason {
    //get the blocking reason for this request
    pub fn block_reason_desc(reasons: &[Self]) -> Option<String> {
        reasons.iter().find(|r| r.action.is_final()).map(|r| r.to_string())
    }
    //get the list of all the monitor reasons for this request
    pub fn monitor_reason_desc(reasons: &[Self]) -> Option<Vec<String>> {
        let matching_reasons: Vec<String> = reasons
            .iter()
            .filter(|r| !r.action.is_final())
            .map(|r| r.to_string())
            .collect();

        if matching_reasons.is_empty() {
            None
        } else {
            Some(matching_reasons)
        }
    }

    pub fn global_filter(id: String, name: String, action: RawActionType, locs: &HashSet<Location>) -> Self {
        let initiator = Initiator::GlobalFilter;
        let (location, extra_locations) = extra_locations(locs.iter());
        BlockReason {
            id,
            name,
            action,
            initiator,
            location,
            extra_locations,
            extra: Value::Null,
        }
    }

    pub fn limit(id: String, name: String, threshold: u64, action: RawActionType) -> Self {
        BlockReason::nodetails(id, name, Initiator::Limit { threshold }, action)
    }

    pub fn phase01_unknown(reason: &str) -> Self {
        BlockReason::nodetails(
            "phase01".to_string(),
            "phase01".to_string(),
            Initiator::Phase01Fail(reason.to_string()),
            RawActionType::Custom,
        )
    }

    pub fn phase02() -> Self {
        BlockReason::nodetails(
            "phase02".to_string(),
            "phase02".to_string(),
            Initiator::Phase02,
            RawActionType::Custom,
        )
    }

    fn nodetails(id: String, name: String, initiator: Initiator, action: RawActionType) -> Self {
        BlockReason {
            id,
            name,
            initiator,
            location: Location::Request,
            action,
            extra_locations: Vec::new(),
            extra: Value::Null,
        }
    }

    pub fn body_too_deep(id: String, name: String, action: RawActionType, expected: usize) -> Self {
        BlockReason {
            id,
            name,
            initiator: Initiator::Restriction {
                tpe: "too deep",
                actual: format!(">{}", expected),
                expected: expected.to_string(),
            },
            location: Location::Body,
            action,
            extra_locations: Vec::new(),
            extra: Value::Null,
        }
    }
    pub fn body_too_large(id: String, name: String, action: RawActionType, actual: usize, expected: usize) -> Self {
        BlockReason {
            id,
            name,
            initiator: Initiator::Restriction {
                tpe: "too large",
                actual: actual.to_string(),
                expected: expected.to_string(),
            },
            location: Location::Body,
            action,
            extra_locations: Vec::new(),
            extra: Value::Null,
        }
    }
    pub fn body_missing(id: String, name: String, action: RawActionType) -> Self {
        BlockReason {
            id,
            name,
            initiator: Initiator::Restriction {
                tpe: "missing body",
                actual: "missing".to_string(),
                expected: "something".to_string(),
            },
            location: Location::Body,
            action,
            extra_locations: Vec::new(),
            extra: Value::Null,
        }
    }
    pub fn body_malformed(
        id: String,
        name: String,
        action: RawActionType,
        actual: &str,
        expected: Option<&str>,
    ) -> Self {
        BlockReason {
            id,
            name,
            initiator: Initiator::Restriction {
                tpe: "malformed body",
                actual: actual.to_string(),
                expected: expected.unwrap_or("well-formed").to_string(),
            },
            location: Location::Body,
            action,
            extra_locations: Vec::new(),
            extra: Value::Null,
        }
    }
    pub fn sqli(id: String, name: String, action: RawActionType, location: Location, fp: String) -> Self {
        BlockReason {
            id,
            name,
            initiator: Initiator::ContentFilter {
                ruleid: format!("sqli:{}", fp),
                risk_level: 3,
            },
            location,
            action,
            extra_locations: Vec::new(),
            extra: Value::Null,
        }
    }
    pub fn xss(id: String, name: String, action: RawActionType, location: Location) -> Self {
        BlockReason {
            id,
            name,
            initiator: Initiator::ContentFilter {
                ruleid: "xss".to_string(),
                risk_level: 3,
            },
            location,
            action,
            extra_locations: Vec::new(),
            extra: Value::Null,
        }
    }
    pub fn too_many_entries(
        id: String,
        name: String,
        action: RawActionType,
        idx: SectionIdx,
        actual: usize,
        expected: usize,
    ) -> Self {
        BlockReason {
            id,
            name,
            initiator: Initiator::Restriction {
                tpe: "too many",
                actual: actual.to_string(),
                expected: expected.to_string(),
            },
            location: Location::from_section(idx),
            action,
            extra_locations: Vec::new(),
            extra: Value::Null,
        }
    }
    pub fn entry_too_large(
        id: String,
        cf_name: String,
        action: RawActionType,
        idx: SectionIdx,
        name: &str,
        actual: usize,
        expected: usize,
    ) -> Self {
        BlockReason {
            id,
            name: cf_name,
            initiator: Initiator::Restriction {
                tpe: "too large",
                actual: actual.to_string(),
                expected: expected.to_string(),
            },
            location: Location::from_name(idx, name),
            action,
            extra_locations: Vec::new(),
            extra: Value::Null,
        }
    }
    pub fn restricted(
        id: String,
        name: String,
        action: RawActionType,
        location: Location,
        actual: String,
        expected: String,
    ) -> Self {
        BlockReason {
            id,
            name,
            initiator: Initiator::Restriction {
                tpe: "restricted",
                actual,
                expected,
            },
            location,
            action,
            extra_locations: Vec::new(),
            extra: Value::Null,
        }
    }
    pub fn acl(id: String, name: String, tags: Tags, stage: AclStage) -> Self {
        let mut tagv = Vec::new();
        let mut locations = HashSet::new();
        for (k, v) in tags.tags.into_iter() {
            tagv.push(k);
            locations.extend(v);
        }
        let action = match stage {
            AclStage::Allow | AclStage::Bypass | AclStage::AllowBot => RawActionType::Monitor,
            AclStage::Deny | AclStage::EnforceDeny => RawActionType::Custom,
            AclStage::DenyBot => RawActionType::Challenge,
        };
        let (location, extra_locations) = extra_locations(locations.iter());

        BlockReason {
            id,
            name,
            initiator: Initiator::Acl { tags: tagv, stage },
            location,
            action,
            extra_locations,
            extra: Value::Null,
        }
    }

    pub fn regroup<'t>(reasons: &'t [Self]) -> HashMap<InitiatorKind, Vec<&'t Self>> {
        let mut out: HashMap<InitiatorKind, Vec<&'t Self>> = HashMap::new();

        for reason in reasons {
            if let Some(kind) = reason.initiator.to_kind() {
                let entry = out.entry(kind).or_default();
                entry.push(reason);
            }
        }

        out
    }

    pub fn serialize_in_map<S: serde::Serializer>(
        &self,
        map: &mut <S as serde::Serializer>::SerializeMap,
    ) -> Result<(), S::Error> {
        self.initiator.serialize_in_map::<S>(map)?;
        self.location.serialize_with_parent::<S>(map)?;
        map.serialize_entry("action", &self.action)?;
        map.serialize_entry("trigger_id", &self.id)?;
        map.serialize_entry("trigger_name", &self.name)?;
        Ok(())
    }
}

pub struct LegacyBlockReason<'t>(&'t BlockReason);

impl<'t> Serialize for LegacyBlockReason<'t> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map: <S as serde::Serializer>::SerializeMap = serializer.serialize_map(None)?;
        map.serialize_entry("initiator", &self.0.initiator.to_kind())?;
        self.0.serialize_in_map::<S>(&mut map)?;
        map.end()
    }
}
