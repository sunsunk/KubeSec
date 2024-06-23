The log is by default sent to stdout. In the Curieproxy containers, it is piped to *filebeat* that will store it
in ElasticSearch.

The log file is a JSON encoded data structure, where the top level is an object with the following members:

 * `timestamp`: time when the request started to be processed, encoded as a string
 * `curiesession`: a session identifier (a string),
 * `curiesession_ids`: extra session identifiers (a list of NV items, see below),
 * `branch`: name of the current branch (taken from the `branch:xxx` tag)
 * `request_id`: unique identifier for the request, provided by either envoy or NGINX `ngx.var.request_id`
 * `security_config`: see the *security config* section
 * `arguments`: a list of NV items representing arguments
 * `path`: query path
	 * raw as submitted
 * `query`: Query string
	 * raw as submitted (with the "?" when presented)
 * `path_parts`: a list of NV items representing path parts,
	 * decoded
 * `authority`: the `:authority` meta data, if it exists, or the *host* header
 * `cookies`: a list of NV items representing cookies
 * `headers`: a list of NV items representing headers
 * `tags`: a list of strings, representing the request tags
 * `ip`: request IP, as a string
 * `method`: request method verb, as a string (uppercased)
 * `response_code`: the response code that was served to the user (integer)
 * `logs`: a list of string, destined for human consumption, with an unspecified format,
 * `processing_stage`: a number representing the stage where the request stopped being processed:
    * 0: initialization, should never happen,
    * 1: security policy level, this means no security policy could be selected,
    * 2: global filter stage,
    * 3: flow control stage (internal, should not happen in a real log),
    * 4: rate limit stage,
    * 5: ACL stage,
    * 6: content filter stage.
 * `trigger_counters`: a list of KV items of the form:
    * `TRIGGER`: length of the `TRIGGER` list,
    Here, `TRIGGER` can be `acl`, `gf` (for global filters), `rl` (for rate limit), `cf` (for content filter), or `cf_restrict` (for content filter restrictions).

 * `acl_triggers`: triggers for the `acl` trigger type (see below),
 * `rl_triggers`: triggers for the `rate_limit` trigger type (see below),
 * `gf_triggers`: triggers for the `global_filter` trigger type (see below),
 * `cf_triggers`: triggers for the `content_filter` trigger type (see below),
 * `cf_restrict_triggers`: triggers for the `content_filter` trigger type (see below),
 * `proxy`: an object many NV items, left undocumented
 * `reason`: a string describing why a decision was reached,
 * `profiling`: an object with NV items, where the name is a string describing the timing source and the value a amount of microseconds since the request started to be processed.
 * `biometrics`: for now, an empty object.

## list of NV items

This represents a dictionary as a list of name/values items, in order to be easier to query by databases. Example:

```json
  "headers": [
    {
      "name": "user-agent",
      "value": "curl/7.68.0"
    },
    {
      "name": "x-forwarded-for",
      "value": "199.0.0.1"
    },
    {
      "name": "host",
      "value": "www.example.com"
    },
    {
      "name": "accept",
      "value": "*/*"
    }
  ]
```

## Security configuration object

This is an object representing the security configuration when the request was matched:

 * `revision`: string, the revision, from the manifest file,
 * `acl_active`: boolean, true if ACL is enabled,
 * `cf_active`: boolean, true if content filters are enabled,
 * `cf_rules`: number of content filter rules that were matched against the request,
 * `rl_rules`: number of "Active" rate limit rules included with the session processing (global or path matched)
 * `gf_rules`: number of global filters included with the session processing
 * `secpolid`: security policy id
 * `secpolentryid`: security policy entry id

## Trigger lists

The fields named `TYPE_triggers` are lists of objects, representing the filter elements that were triggered.
Each of these objects contain information about the part of the request that triggered, as well as information
specific to the type of trigger.

* `trigger_id`: string
* `trigger_name`: string
* `action`: string representing the action type
* `extra`: an optional field, for future extensibility

`TYPE` can be one of:
 * `fg` (global filter)
 * `rl` (rate limit)
 * `acl`
 * `cf` (content filter)
 * `cf_restrict` (content filter restrictions)

### Location data

The following entries are **all optional**:
 * `section`, can be `attributes`, `uri`, `referer`, `headers`, `body`, `cookies` or `plugins`;
 * `name`, name of the argument, header, path part or cookie that triggered the response;
 * `value`, actual value that triggered the response.

Here are some examples of location data:

 * `{"value":"part","name":5,"section":"referer"}` is the 5th path part of the referer URI,
 * `{"value":"value","name":"name","section":"body"}` is an argument in the body
 * `{"name":"ip","section":"attributes"}` is the IP address

### Trigger specific entries

The following triggers are defined:

#### ACL triggers

Contains:
  * `tags`, list of strings, the list of tags that matched the ACL column
  * `acl_action`, a string, the ACL column

For example:

```json
{
  "trigger_name": "from tags",
  "trigger_id": "FROMTAGS",
  "acl_action": "deny_bot",
  "value": "denybot",
  "tags": [
    "denybot"
  ],
  "action": "challenge",
  "name": "denybot",
  "section": "uri"
}
```

#### Rate limit triggers

Contains:
  * `threshold`, a number, representing the limit threshold

#### Global filter triggers

No specific fields for global filters.

For example:

```json
{
  "section": "headers",
  "value": "header_value",
  "trigger_name": "Filter header",
  "action": "skip",
  "name": "test-global-filter-trigger",
  "trigger_id": "filter-header"
}
```

#### Content filter rules triggers

Contains:

  * `ruleid`, a string, the id of the matching rule,
  * `risk_level`, a number, the risk level of the matching rule.

For example:

```json
{
  "trigger_name": "default contentfilter",
  "ruleid": "100016",
  "section": "uri",
  "value": "xp_cmdshell_xp_cmdshell_xp_cmdshell_xp_cmdshell_xp_cmdshell_",
  "trigger_id": "__default__",
  "action": "monitor",
  "name": "arg",
  "risk_level": 5
}
```

#### Content filter restriction triggers

Contains:

  * `type`, a string, can be `too deep`, `too large`, `missing body`, `malformed body`, `too many`, `too large`, `restricted`
  * `actual`, a string
  * `expected`, a string

For example:

```json
{
  "trigger_name": "expect xml",
  "section": "body",
  "trigger_id": "expectxml",
  "type": "malformed body",
  "actual": "no content type specified",
  "expected": "[Xml]",
  "action": "custom"
}
```

# Sample log

```json
{
  "acl_triggers": [
    {
      "acl_action": "deny",
      "action": "custom",
      "tags": [
        "all"
      ],
      "trigger_id": "jwt-acl",
      "trigger_name": "jwt acl test"
    }
  ],
  "arguments": [],
  "authority": "jwt-test.com",
  "cf_restrict_triggers": [],
  "cf_triggers": [],
  "cookies": [],
  "curiesession": "e74ad58c1935e7f330bdb86cec282ba8f5f44fbe70677a63d178c0f5",
  "curiesession_ids": [],
  "gf_triggers": [
    {
      "action": "monitor",
      "trigger_id": "45f5dda5931e",
      "trigger_name": "Sante test"
    }
  ],
  "headers": [
    {
      "name": "x-forwarded-for",
      "value": "10.8.8.1"
    },
    {
      "name": "user-agent",
      "value": "dummy"
    }
  ],
  "ip": "10.8.8.1",
  "logs": [
    "D 0µs Inspection init",
    "...",
    "D 661µs ACL result: bot(none)/human(denied [\"all\"])"
  ],
  "method": "GET",
  "path": "/jwt/acl",
  "path_parts": [
    {
      "name": "part2",
      "value": "acl"
    },
    {
      "name": "path",
      "value": "/jwt/acl"
    },
    {
      "name": "part1",
      "value": "jwt"
    }
  ],
  "processing_stage": 5,
  "profiling": [
    {
      "name": "secpol",
      "value": 95
    },
    {
      "name": "mapping",
      "value": 477
    },
    {
      "name": "flow",
      "value": 612
    },
    {
      "name": "limit",
      "value": 618
    },
    {
      "name": "acl",
      "value": 666
    },
    {
      "name": "content_filter",
      "value": null
    }
  ],
  "proxy": [
    {
      "name": "geo_long",
      "value": null
    },
    {
      "name": "geo_lat",
      "value": null
    },
    {
      "name": "geo_as_name",
      "value": null
    },
    {
      "name": "geo_as_domain",
      "value": null
    },
    {
      "name": "geo_as_type",
      "value": null
    },
    {
      "name": "geo_company_country",
      "value": null
    },
    {
      "name": "geo_company_domain",
      "value": null
    },
    {
      "name": "geo_company_type",
      "value": null
    },
    {
      "name": "geo_mobile_carrier",
      "value": null
    },
    {
      "name": "geo_mobile_country",
      "value": null
    },
    {
      "name": "geo_mobile_mcc",
      "value": null
    },
    {
      "name": "geo_mobile_mnc",
      "value": null
    },
    {
      "name": "container",
      "value": "265c8e0e1a22"
    }
  ],
  "query": null,
  "reason": "Custom - acl Deny [\"all\"] - [request]",
  "request_id": null,
  "response_code": 403,
  "rl_triggers": [],
  "security_config": {
    "acl_active": true,
    "cf_active": false,
    "cf_rules": 0,
    "gf_rules": 25,
    "revision": "unknown",
    "rl_rules": 1
  },
  "tags": [
    "host:jwt-test-com",
    "all",
    "ip:10-8-8-1",
    "geo-continent-name:nil",
    "geo-asn:nil",
    "securitypolicy-entry:default",
    "geo-region:nil",
    "geo-org:nil",
    "cookies:0",
    "geo-country:nil",
    "geo-subregion:nil",
    "network:nil",
    "sante",
    "aclid:jwt-acl",
    "bot",
    "geo-continent-code:nil",
    "headers:2",
    "args:0",
    "aclname:jwt-acl-test",
    "contentfilterid:--default--",
    "geo-city:nil",
    "securitypolicy:test-for-the-jwt-plugin",
    "contentfiltername:default-contentfilter",
    "status:403",
    "status-class:4xx"
  ],
  "timestamp": "2022-12-27T09:39:02.707558557Z",
  "trigger_counters": {
    "acl": 1,
    "cf": 0,
    "cf_restrict": 0,
    "gf": 1,
    "rl": 0
  }
}

```