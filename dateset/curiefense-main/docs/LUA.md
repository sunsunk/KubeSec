# The Curiefense Lua API

When the `curiefense.so` file is in a path that Lua imports, the curiefense module can be loaded in any Lua script using the standard:

```lua
local curiefense  = require "curiefense"
```


## Configuration loading

### `lua_reload_conf`

The `curiefense.lua_reload_conf` function takes two arguments:

 * the first argument is optional, and is a JSON-encoded string representing a list of strings;
 * the second argument is optional, and is a string representing the path to the configuration
   directory. If missing, it defaults to `/cf-config/current/config`.

The first argument is the list of files that needs to be reloaded. If this argument is nil or the
list is empty, then all the files are reloaded. If this function is not called before the other
functions are called, they will work with an empty configuration.

The list of files is:
  * `actions.json`
  * `acl-profiles.json`
  * `contentfilter-profiles.json`
  * `contentfilter-rules.json`
  * `globalfilter-lists.json`
  * `limits.json`
  * `securitypolicy.json`
  * `flow-control.json`
  * `virtual-tags.json`

Unrecognized files are ignored.

The list of files is JSON encoded so that JSON-encoded arguments can directly be passed from the web
server without having to decode them.

## Request inspection

### Filtering arguments

The functions `inspect_request`, `inspect_request_init` and `test_inspect_request` all take a single argument, a Lua table with the following content:
 * `loglevel`, a string. Can be `debug`, `info`, `warn` or `err`.
 * `meta`, table, contains keys `method`, `path` and optionally `authority` and `x-request-id`.
 * `headers`, a table where the keys are header names and values are header values.
 * `body`, optional string, containing the whole body.
 * `ip`, string representation of the IP address.
 * `hops`, optional number. When set the IP is computed from the `x-forwarded-for header`, defaulting to the `ip` argument on failure.
 * `secpolid`, optional string. When set, bypass host name matching for security policy selection, and directly selects the corresponding policy.
 * `configpath`, path to the lua configuration files, defaults to `/cf-config/current/config`.
 * `humanity`, optional boolean, only used for the test functions.

### The `LuaInspectionResult` user data

This type is returned by many functions, as described below. It exposes the following attributes:

 * `error`, nil when there were no errors, a string describing the error otherwise.
 * `blocking`, a boolean telling if a blocking action should be taken in response to the request.
 * `tags`, the list of tags, or nil if the request handling aborted before they could be set.
 * `logs`, a list of strings containing the logs collected during request handling.
 * `response`, a JSON-encoded string representing the action that should be taken by the proxy

And the following method:

 * `request_map`, takes a single argument, the *proxy* table where keys and values must be strings.
 This returns the JSON-encoded log for the request.

### `inspect_request`

Takes a single argument (see the *Filtering arguments* section), and returns a `LuaInspectionResult`.
This is the easiest to use function, as it does all the work with a single call, but it is *blocking* during Redis queries.

### Non blocking inspection

The non blocking inspection works using the following workflow:

 * initialization with `inspect_request_init`, returning a *phase 1* `InitResult`;
 * unless the `InitResult` is *decided*, caller performs Redis queries related to flow-control;
 * the `InitResult` is handled by the `inspect_request_flows` function, returning a *phase 2* `InitResult`;
 * unless the `InitResult` is *decided*, caller performs Redis queries related to rate-limiting;
 * finally, the result is handled by the `lua_request_process` function.

#### Initialization
`inspect_request_init` takes a single argument (see the *Filtering arguments* section).
It returns a *phase 1* `InitResult`, which behaves just like a `LuaInspectionResult`, except that it also exposes:

 * a `decided` attribute, which, when true, means that no further processing should take place and
   the related `response` should be processed.
 * a `desc` attribute, a string mainly for debug purposes.
 * a `flows` attribute, which is a list of `LuaFlowCheck`.

#### Flow checking
Each `LuaFlowCheck` has to be handled by the caller. They expose the following attributes:
  * `key`: Redis key to query
  * `step`: step the flow is at
  * `is_last`: boolean, true if this is the last step
  * `name`: name of the flow control rule
  * `tags`: list of tags to add if the flow matches
  * `timeframe`: time frame for the flow control process

They also expose a `result` method that returns a `LuaFlowResult` and takes a string argument that can have the following content:
  * `lastok`, it was the last step, and the flow was correctly followed
  * `lastblock`, it was the last step, and it was incorrectly reached
  * `nonlast`, this was not the last step

#### Flow processing
The `inspect_request_flows` takes two arguments: the first argument is the *phase 1* `InitResult`, and the second argument
is the list of `LuaFlowResult` that has been created previously.

It returns a *phase 2* `InitResult`, which behaves just like a `LuaInspectionResult`, except that it also exposes:

 * a `decided` attribute, which, when true, means that no further processing should take place and
   the related `response` should be processed.
 * a `desc` attribute, a string mainly for debug purposes.
 * a `limits` attribute, which is a list of `LuaLimitCheck`.

#### Limit checking
Each `LuaLimitCheck` has to be handled by the caller. They expose the following attributes:
  * `key`: Redis key to query
  * `pairwith`:  optional Redis *pair with* key to query
  * `zero_limits`: true if this is a *zero limit*, that is a limit that is always triggered
  * `timeframe`: limit time frame

It also exposes a `result` method that takes a single argument (a number, representing the amount of events that ocured in the given time frame)
and returns a `LuaLimitResult`.

#### End of processing

The `lua_request_process` takes two arguments: the first argument is the *phase 2* `InitResult`, and the second argument
is the list of `LuaLimitResult` that has been created previously.

It returns a `LuaInspectionResult`.

## Aggregated values

The `aggregated_values` function returns a JSON-encoded string representing the aggregated values for the configured time frame (see environment variables).