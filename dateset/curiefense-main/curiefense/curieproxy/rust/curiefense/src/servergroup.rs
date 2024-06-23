use std::sync::Arc;

use crate::config::custom::Site;
use crate::config::Config;
use crate::logs::Logs;

/// finds the server group matching a given request, based on the configuration
/// and the selected server group id
pub fn match_servergroup<'a>(cfg: &'a Config, logs: &mut Logs, selected_sergrp: Option<&str>) -> Arc<Site> {
    let site: Arc<Site> = match selected_sergrp {
        None => Arc::new(Site::default()),
        Some(sergrpid) => match cfg.servergroups_map.get(sergrpid) {
            Some(s) => Arc::new(s.clone()),
            None => {
                logs.error(|| format!("Can't find sergrp id {}", sergrpid));
                Arc::new(Site::default())
            }
        },
    };

    logs.debug(|| format!("Selected server group entry {}", site.id));
    site
}
