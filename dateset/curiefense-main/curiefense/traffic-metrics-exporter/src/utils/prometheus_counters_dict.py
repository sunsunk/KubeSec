from enum import Enum


class CounterTypes(Enum):
    REGULAR = 1
    # counter additionally labeled by "key"
    COUNTER_BY_KEY = 2
    # elements that looks like dict
    # E.g. {"args":0,"attrs":0,"body":0,"headers":0,"uri":0}
    COUNTER_OBJECT_BY_KEY = 3
    AVERAGE = 4
    MAX = 5
    MIN = 6
    # args, cookies, headers amounts per request
    MAX_PER_REQUEST = 7
    AVG_PER_REQUEST = 8


REGULAR = CounterTypes.REGULAR
AVERAGE = CounterTypes.AVERAGE
MAX = CounterTypes.MAX
MIN = CounterTypes.MIN
MAX_PER_REQUEST = CounterTypes.MAX_PER_REQUEST
AVG_PER_REQUEST = CounterTypes.AVG_PER_REQUEST
COUNTER_BY_KEY = CounterTypes.COUNTER_BY_KEY
COUNTER_OBJECT_BY_KEY = CounterTypes.COUNTER_OBJECT_BY_KEY


# mapping of counters to REGULAR, SESSION and PROCESSING_TIME. the two other ones are recognized by regex
counters_format = {
    "hits": {"type": REGULAR},
    "blocks": {"type": REGULAR},
    "report": {"type": REGULAR},
    "human": {"type": REGULAR},
    "bot": {"type": REGULAR},
    "challenge": {"type": REGULAR},
    "active": {"type": REGULAR},
    "passed": {"type": REGULAR},
    "reported": {"type": REGULAR},
    "requests_triggered_acl_active": {"type": REGULAR},
    "requests_triggered_acl_report": {"type": REGULAR},
    "requests_triggered_cf_active": {"type": REGULAR},
    "requests_triggered_cf_report": {"type": REGULAR},
    "requests_triggered_globalfilter_active": {"type": REGULAR},
    "requests_triggered_globalfilter_report": {"type": REGULAR},
    "requests_triggered_ratelimit_active": {"type": REGULAR},
    "requests_triggered_ratelimit_report": {"type": REGULAR},
    "risk_level_active": {"type": COUNTER_BY_KEY, "label": "level"},
    "risk_level_report": {"type": COUNTER_BY_KEY, "label": "level"},
    "top_aclid_active": {"type": COUNTER_BY_KEY, "label": "aclid"},
    "top_aclid_passed": {"type": COUNTER_BY_KEY, "label": "aclid"},
    "top_aclid_reported": {"type": COUNTER_BY_KEY, "label": "aclid"},
    "top_country_active": {"type": COUNTER_BY_KEY, "label": "country"},
    "top_country_passed": {"type": COUNTER_BY_KEY, "label": "country"},
    "top_country_reported": {"type": COUNTER_BY_KEY, "label": "country"},
    "top_asn_active": {"type": COUNTER_BY_KEY, "label": "asn"},
    "top_asn_passed": {"type": COUNTER_BY_KEY, "label": "asn"},
    "top_asn_reported": {"type": COUNTER_BY_KEY, "label": "asn"},
    "top_ruleid_active": {"type": COUNTER_BY_KEY, "label": "ruleid"},
    "top_ruleid_passed": {"type": COUNTER_BY_KEY, "label": "ruleid"},
    "top_ruleid_reported": {"type": COUNTER_BY_KEY, "label": "ruleid"},
    "top_tags_active": {"type": COUNTER_BY_KEY, "label": "tag"},
    "top_tags_passed": {"type": COUNTER_BY_KEY, "label": "tag"},
    "top_tags_reported": {"type": COUNTER_BY_KEY, "label": "tag"},
    "top_rtc_active": {"type": COUNTER_BY_KEY, "label": "tag"},
    "top_rtc_passed": {"type": COUNTER_BY_KEY, "label": "tag"},
    "top_rtc_reported": {"type": COUNTER_BY_KEY, "label": "tag"},
    "methods": {"type": COUNTER_BY_KEY, "label": "method"},
    "status": {"type": COUNTER_BY_KEY, "label": "code"},
    "status_classes": {"type": COUNTER_BY_KEY, "label": "code_class"},
    "section_active": {"type": COUNTER_OBJECT_BY_KEY, "label": "section"},
    "section_passed": {"type": COUNTER_OBJECT_BY_KEY, "label": "section"},
    "section_reported": {"type": COUNTER_OBJECT_BY_KEY, "label": "section"},
    "unique_ip_blocked": {"type": AVERAGE},
    "unique_uri_blocked": {"type": AVERAGE},
    "unique_user_agent_blocked": {"type": AVERAGE},
    "unique_asn_blocked": {"type": AVERAGE},
    "unique_country_blocked": {"type": AVERAGE},
    "unique_asn_active": {"type": AVERAGE},
    "unique_country_active": {"type": AVERAGE},
    "unique_ip_active": {"type": AVERAGE},
    "unique_session_active": {"type": AVERAGE},
    "unique_uri_active": {"type": AVERAGE},
    "unique_user_agent_active": {"type": AVERAGE},
    "unique_asn": {"type": AVERAGE},
    "unique_country": {"type": AVERAGE},
    "unique_ip": {"type": AVERAGE},
    "unique_asn_passed": {"type": AVERAGE},
    "unique_country_passed": {"type": AVERAGE},
    "unique_ip_passed": {"type": AVERAGE},
    "unique_session_passed": {"type": AVERAGE},
    "unique_uri_passed": {"type": AVERAGE},
    "unique_user_agent_passed": {"type": AVERAGE},
    "unique_asn_reported": {"type": AVERAGE},
    "unique_country_reported": {"type": AVERAGE},
    "unique_ip_reported": {"type": AVERAGE},
    "unique_session_reported": {"type": AVERAGE},
    "unique_uri_reported": {"type": AVERAGE},
    "unique_user_agent_reported": {"type": AVERAGE},
    "unique_session": {"type": AVERAGE},
    "unique_uri": {"type": AVERAGE},
    "unique_user_agent": {"type": AVERAGE},
    "top_max_args_per_request": {"type": MAX_PER_REQUEST, "label": "group"},
    "top_max_cookies_per_request": {"type": MAX_PER_REQUEST, "label": "group"},
    "top_max_headers_per_request": {"type": MAX_PER_REQUEST, "label": "group"},
    "top_request_per_args": {"type": AVG_PER_REQUEST, "label": "group"},
    "top_request_per_cookies": {"type": AVG_PER_REQUEST, "label": "group"},
    "top_request_per_headers": {"type": AVG_PER_REQUEST, "label": "group"},
    "processing_time_average": {"type": AVERAGE},
    "processing_time_max": {"type": AVERAGE},
    "processing_time_min": {"type": MIN},
    "bytes_sent_average": {"type": MAX},
    "bytes_sent_min": {"type": MAX},
    "bytes_sent_max": {"type": MIN},
}


name_changes = {}

# validating format validity, in case new keys will be entered
for counter, value in counters_format.items():
    if value["type"] not in [
        REGULAR,
        AVERAGE,
        MAX,
        MIN,
        MAX_PER_REQUEST,
        AVG_PER_REQUEST,
        COUNTER_BY_KEY,
        COUNTER_OBJECT_BY_KEY,
    ]:
        raise TypeError(f"{counter} is not of a legal type in counters_format")
