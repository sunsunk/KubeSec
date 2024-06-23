from __future__ import nested_scopes
import codecs
import base64
import json

import pydash
from flask_restx import fields

DOCUMENTS_PATH = {
    "actions": "config/json/actions.json",
    "ratelimits": "config/json/limits.json",
    "securitypolicies": "config/json/securitypolicy.json",
    "contentfilterrules": "config/json/contentfilter-rules.json",
    "contentfilterprofiles": "config/json/contentfilter-profiles.json",
    "aclprofiles": "config/json/acl-profiles.json",
    "globalfilters": "config/json/globalfilter-lists.json",
    "flowcontrol": "config/json/flow-control.json",
    "virtualtags": "config/json/virtual-tags.json",
    "custom": "config/json/custom.json",
}

BLOBS_PATH = {
    "geolite2asn": "config/maxmind/GeoLite2-ASN.mmdb",
    "geolite2country": "config/maxmind/GeoLite2-Country.mmdb",
    "geolite2city": "config/maxmind/GeoLite2-City.mmdb",
    "ipinfo_asn": "config/ipinfo/IPInfo-ASN.mmdb",
    "ipinfo_carrier": "config/ipinfo/IPInfo-Carrier.mmdb",
    "ipinfo_standard_company": "config/ipinfo/IPInfo-Standard-Company.mmdb",
    "ipinfo_standard_location": "config/ipinfo/IPInfo-Standard-Location.mmdb",
    "ipinfo_standard_privacy": "config/ipinfo/IPInfo-Standard-Privacy.mmdb",
    "customconf": "config/customconf.tar.gz",
}

BLOBS_BOOTSTRAP = {
    "geolite2asn": b"",
    "geolite2country": b"",
    "geolite2city": b"",
    "customconf": b"",
}


def _get_existing_keys(target, keys):
    return list(filter(None, map(target.get, keys)))


def jblob2bytes(jblob):
    fmt = jblob["format"]
    jraw = jblob["blob"]
    if fmt == "json":
        return json.dumps(jraw).encode("utf8")
    elif fmt == "string":
        return jraw.encode("utf8")
    elif fmt == "base64" or fmt.endswith("+base64"):
        jraw = codecs.decode(jraw.encode("utf8"), "base64")
        if "+" in fmt:
            cmp, b = fmt.rsplit("+", 1)
            if cmp not in ["zip", "bz2"]:
                raise Exception("unknown blob format: [%s]" % fmt)
            jraw = codecs.decode(jraw, cmp)
        return jraw
    raise Exception("unknown blob format: [%s]" % fmt)


def bytes2jblob(b, fmthint=None):
    try:
        if fmthint == "json":
            c = json.loads(b.decode("utf-8"))
            return {"format": "json", "blob": c}
    except:
        pass
    compb = codecs.encode(b, "bz2")
    if len(compb) < len(b):
        b = compb
        fmt = "bz2+base64"
    else:
        fmt = "base64"
    bl = base64.b64encode(b).decode("utf-8")
    return {"format": fmt, "blob": bl}


def model_invert_names(model):
    """
    Invert key names in a model using fields attribute if exists.

    Args:
        model (Model): model to invert.

    Returns
        Model: inverted model
    """

    mod = model.clone(model.name)
    for key in list(mod):
        _field_invert_names(mod[key])
        if mod[key].attribute:
            new_key = mod[key].attribute
            mod[new_key] = mod[key]
            mod[new_key].attribute = key
            del mod[key]
    return mod


def dict_to_path_value(map, path="", starting_path_list=None):
    """
    Creates a list of path and value dicts for a map.

    Args:
        map (dict): dictionary to create the list for.
        path (String): current path, used for recursion.
        starting_path_list (List): list to append new values to, default None to return a new list.

    Returns
        List: list of path and value pairs
    """

    if starting_path_list == None:
        starting_path_list = []
    if not isinstance(map, dict):
        starting_path_list.append({"path": path, "value": map})
    else:
        for key, value in sorted(map.items()):
            new_path = "{}.{}".format(path, key) if path else "{}".format(key)
            dict_to_path_value(value, new_path, starting_path_list)
    return starting_path_list
