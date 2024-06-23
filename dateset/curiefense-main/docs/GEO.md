# Curiefense geographic IP address lookup

Curiefense support using [Maxmind GeoIP](https://www.maxmind.com/en/geoip2-services-and-databases)
or [ipinfo](https://ipinfo.io/) to perform ip address lookup.

By default, curiefense uses Maxmind GeoLite IP service. It is not possible to uses the two providers at
the same time.

## Maxmind

| Variable name   | Default value                       | Description                                                                                                        |
| --------------- | ----------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| MAXMIND_ROOT    | `/cf-config/current/config/maxmind` | Path to the root directory containing maxmind geoip databases                                                      |
| MAXMIND_COUNTRY | `GeoLite2-Country.mmdb`             | Path to the [country](https://www.maxmind.com/en/geoip2-country-database) database inside `MAXMIND_ROOT` directory |
| MAXMIND_CITY    | `GeoLite2-City.mmdb`                | Path to the [city](https://www.maxmind.com/en/geoip2-city) database inside `MAXMIND_ROOT` directory                |
| MAXMIND_ASN     | `GeoLite2-ASN.mmdb`                 | Path to the ASN database inside `MAXMIND_ROOT` directory                                                           |

A version of GeoLite2 IP databases are already included in this repository so geographic ip address
lookup works by default.

## Ipinfo

ipinfo can be enabled by setting the environment variable `USE_IPINFO` to `true`.

| Variable name   | Default value | Description                                                                                                   |
| --------------- | ------------- | ------------------------------------------------------------------------------------------------------------- |
| USE_IPINFO      | `false`       | Set to `true` to enable using Ipinfo instead of GeoIP                                                         |
| IPINFO_ROOT     | -             | Path to the root directory containing ipinfo databases                                                        |
| IPINFO_LOCATION | -             | Path to the [location](https://ipinfo.io/products/ip-geolocation-api) database inside `IPINFO_ROOT` directory |
| IPINFO_COMPANY  | -             | Path to the [company](https://ipinfo.io/products/ip-company-api) database inside `IPINFO_ROOT` directory      |
| IPINFO_ASN      | -             | Path to the [ASN](https://ipinfo.io/products/asn-api) database inside `IPINFO_ROOT` directory                 |
| IPINFO_PRIVACY  | -             | Path to the [privacy](https://ipinfo.io/products/proxy-vpn-detection-api) database inside `IPINFO_ROOT` directory                                                   |
| IPINFO_CARRIER  | -             | Path to the [carrier](https://ipinfo.io/products/ip-carrier-api) database inside `IPINFO_ROOT` directory      |
