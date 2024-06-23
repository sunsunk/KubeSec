use std::collections::HashMap;

use crate::config::raw::RawSite;
use crate::logs::Logs;

/// Contains objects for the custom.json file

#[derive(Debug, Clone, serde::Deserialize)]
pub struct Site {
    pub id: String,
    pub name: String,
    // pub mobile_sdk: String,
    pub challenge_cookie_domain: String,
}

impl Default for Site {
    fn default() -> Self {
        Self {
            id: ("siteid".to_string()),
            name: ("site name".to_string()),
            // mobile_sdk: ("mobile sdk".to_string()),
            challenge_cookie_domain: "$host".to_string(),
        }
    }
}

impl Site {
    pub fn resolve(logs: &mut Logs, raw_sites: Vec<RawSite>) -> HashMap<String, Site> {
        let mut sites_map: HashMap<String, Site> = HashMap::new();
        for raw_site in raw_sites {
            let challenge_cookie_domain = raw_site
                .challenge_cookie_domain
                .as_ref()
                .map(|domain| {
                    if domain.is_empty() {
                        "$host".to_string()
                    } else {
                        domain.clone()
                    }
                })
                .unwrap_or_else(|| "$host".to_string());

            let site = Site {
                id: raw_site.id.clone(),
                name: raw_site.name.clone(),
                // mobile_sdk: raw_site.mobile_sdk.clone(),
                challenge_cookie_domain,
            };
            sites_map.insert(raw_site.id.clone(), site);
        }
        sites_map
    }
}
