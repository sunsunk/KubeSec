//! Geographic lookup from IP address.
//!
//! The intelligence is provided by through MaxMind GeoIP2 or ipinfo. By default
//! MaxMind GeoIP2 is used with free database, but you can use ipinfo instead by
//! setting the enviroment variable to `USE_IPINFO`.

use anyhow::anyhow;
use ipnet::IpNet;
use lazy_static::lazy_static;
use maxminddb::{
    geoip2::{Asn, City, Country},
    Reader,
};
use serde::Deserialize;

#[cfg(not(test))]
use std::ops::Deref;
use std::{collections::HashMap, net::IpAddr, path::PathBuf};

use crate::ipinfo::{AsnDetails, CarrierDetails, CompanyDetails, LocationDetails, PrivacyDetails};

/// From https://github.com/ipinfo/rust/blob/master/assets/countries.json
const IPINFO_COUNTRY_NAME_RAW: &str = include_str!("../assets/ipinfo/countries.json");
/// From https://github.com/ipinfo/rust/blob/master/assets/eu.json
const IPINFO_COUNTRY_IN_EU_RAW: &str = include_str!("../assets/ipinfo/eu.json");
/// https://github.com/ipinfo/rust/blob/master/assets/continent.json
const IPINFO_CONTINENT_RAW: &str = include_str!("../assets/ipinfo/continent.json");

#[allow(dead_code)]
struct MaxmindGeo {
    asn: Reader<Vec<u8>>,
    country: Reader<Vec<u8>>,
    city: Reader<Vec<u8>>,
}

#[allow(dead_code)]
struct IpinfoGeo {
    location: Reader<Vec<u8>>,
    company: Reader<Vec<u8>>,
    asn: Reader<Vec<u8>>,
    privacy: Reader<Vec<u8>>,
    carrier: Reader<Vec<u8>>,
}

#[derive(Debug, Deserialize)]
pub struct IpInfoContinent<'a> {
    pub code: &'a str,
    pub name: &'a str,
}

lazy_static! {
    // as they are lazy, these loads will not be triggered in test mode
    pub static ref USE_IPINFO: bool = std::env::var("USE_IPINFO").map(|s| s.parse().unwrap_or(false)).unwrap_or(false);

    static ref MAXMIND: anyhow::Result<MaxmindGeo> = {
        let maxmind_root = std::env::var("MAXMIND_ROOT").unwrap_or_else(|_| "/cf-config/current/config/maxmind".to_string());
        let maxmind_asn = std::env::var("MAXMIND_ASN").unwrap_or_else(|_| "GeoLite2-ASN.mmdb".to_string());
        let maxmind_country = std::env::var("MAXMIND_COUNTRY").unwrap_or_else(|_| "GeoLite2-Country.mmdb".to_string());
        let maxmind_city = std::env::var("MAXMIND_CITY").unwrap_or_else(|_| "GeoLite2-City.mmdb".to_string());

        let root_path = PathBuf::from(maxmind_root);
        let mut asn_path = root_path.clone();
        asn_path.push(maxmind_asn);
        let mut country_path = root_path.clone();
        country_path.push(maxmind_country);
        let mut city_path = root_path;
        city_path.push(maxmind_city);
        Reader::open_readfile(asn_path)
            .and_then(|asn| Reader::open_readfile(country_path)
            .and_then(|country| Reader::open_readfile(city_path)
            .map(|city| MaxmindGeo { asn, country, city } ))).map_err(|rr| anyhow!("{}", rr))
    };


    static ref IPINFO: anyhow::Result<IpinfoGeo> = {
        let ipinfo_root = std::env::var("IPINFO_ROOT");
        let ipinfo_location = std::env::var("IPINFO_LOCATION");
        let ipinfo_company = std::env::var("IPINFO_COMPANY");
        let ipinfo_asn = std::env::var("IPINFO_ASN");
        let ipinfo_privacy = std::env::var("IPINFO_PRIVACY");
        let ipinfo_carrier = std::env::var("IPINFO_CARRIER");

        match (ipinfo_root, ipinfo_location, ipinfo_company, ipinfo_asn, ipinfo_privacy, ipinfo_carrier) {
            (Ok(root), Ok(location), Ok(company), Ok(asn), Ok(privacy), Ok(carrier)) => {
                    let root_path = PathBuf::from(root);
                    let mut location_path = root_path.clone();
                    location_path.push(location);
                    let mut company_path = root_path.clone();
                    company_path.push(company);
                    let mut asn_path = root_path.clone();
                    asn_path.push(asn);
                    let mut privacy_path = root_path.clone();
                    privacy_path.push(privacy);
                    let mut carrier_path = root_path;
                    carrier_path.push(carrier);
                    Reader::open_readfile(location_path)
                        .and_then(|location| Reader::open_readfile(company_path)
                        .and_then(|company| Reader::open_readfile(privacy_path)
                        .and_then(|asn| Reader::open_readfile(asn_path)
                        .and_then(|privacy| Reader::open_readfile(carrier_path)
                        .map(|carrier| IpinfoGeo { location, company, asn, privacy, carrier } ))))).map_err(|rr| anyhow!("{}", rr))
            }
            _ => Err(anyhow!("Could not read ipinfo")) // TODO: add actual error in Err
        }
    };
    static ref IPINFO_COUNTRY_NAME: HashMap<&'static str, &'static str> = serde_json::from_str(IPINFO_COUNTRY_NAME_RAW).unwrap();
    static ref IPINFO_COUNTRY_IN_EU: Vec<&'static str> = serde_json::from_str(IPINFO_COUNTRY_IN_EU_RAW).unwrap();
    static ref IPINFO_CONTINENT: HashMap<&'static str, IpInfoContinent<'static>> = serde_json::from_str(IPINFO_CONTINENT_RAW).unwrap();

}

pub fn ipinfo_resolve_country_name(country_iso: &str) -> Option<String> {
    IPINFO_COUNTRY_NAME.get(country_iso).map(|c| c.to_string())
}

pub fn ipinfo_country_in_eu(country_iso: &str) -> bool {
    IPINFO_COUNTRY_IN_EU.contains(&country_iso)
}

pub fn ipinfo_resolve_continent(country_iso: &str) -> Option<&IpInfoContinent<'static>> {
    IPINFO_CONTINENT.get(country_iso)
}

#[cfg(not(test))]
fn compute_network<T>(data: T, addr: IpAddr, prefix_len: usize) -> (T, Option<IpNet>) {
    let network = IpNet::new(addr, prefix_len as u8).ok();
    (data, network)
}

/// Retrieves the english name of the country associated with this IP
#[cfg(not(test))]
pub fn get_maxmind_country(addr: IpAddr) -> Result<(Country<'static>, Option<IpNet>), String> {
    if *USE_IPINFO {
        return Err("Maxmind is not enabled. You can enable it by setting USE_IPINFO=false".to_string());
    }

    match MAXMIND.deref() {
        Err(rr) => Err(format!("could not read country db: {}", rr)),
        Ok(maxmind) => match maxmind.country.lookup_prefix(addr) {
            Ok((country, prefix_len)) => Ok(compute_network::<Country>(country, addr, prefix_len)),
            Err(rr) => Err(format!("{}", rr)),
        },
    }
}

#[cfg(not(test))]
pub fn get_maxmind_asn(addr: IpAddr) -> Result<(Asn<'static>, Option<IpNet>), String> {
    if *USE_IPINFO {
        return Err("Maxmind is not enabled. You can enable it by setting USE_IPINFO=false".to_string());
    }

    match MAXMIND.deref() {
        Err(rr) => Err(format!("could not read ASN db: {}", rr)),
        Ok(maxmind) => match maxmind.asn.lookup_prefix(addr) {
            Ok((asn, prefix_len)) => Ok(compute_network::<Asn>(asn, addr, prefix_len)),
            Err(rr) => Err(format!("{}", rr)),
        },
    }
}

#[cfg(not(test))]
pub fn get_maxmind_city(addr: IpAddr) -> Result<(City<'static>, Option<IpNet>), String> {
    if *USE_IPINFO {
        return Err("Maxmind is not enabled. You can enable it by setting USE_IPINFO=false".to_string());
    }

    match MAXMIND.deref() {
        Err(rr) => Err(format!("could not read city db: {}", rr)),
        Ok(maxmind) => match maxmind.city.lookup_prefix(addr) {
            Ok((city, prefix_len)) => Ok(compute_network::<City>(city, addr, prefix_len)),
            Err(rr) => Err(format!("{}", rr)),
        },
    }
}

#[cfg(not(test))]
pub fn get_ipinfo_location(addr: IpAddr) -> Result<(LocationDetails, Option<IpNet>), String> {
    if !(*USE_IPINFO) {
        return Err("Ipinfo is not enabled. You can enable it by setting USE_IPINFO=true".to_string());
    }

    match IPINFO.deref() {
        Err(rr) => Err(format!("could not read city db: {}", rr)),
        Ok(ipinfo) => match ipinfo.location.lookup_prefix(addr) {
            Ok((loc, prefix_len)) => Ok(compute_network::<LocationDetails>(loc, addr, prefix_len)),
            Err(rr) => Err(format!("{}", rr)),
        },
    }
}

#[cfg(not(test))]
pub fn get_ipinfo_privacy(addr: IpAddr) -> Result<(PrivacyDetails, Option<IpNet>), String> {
    if !(*USE_IPINFO) {
        return Err("Ipinfo is not enabled. You can enable it by setting USE_IPINFO=true".to_string());
    }

    match IPINFO.deref() {
        Err(rr) => Err(format!("could not read city db: {}", rr)),
        Ok(ipinfo) => match ipinfo.privacy.lookup_prefix(addr) {
            Ok((privacy, prefix_len)) => Ok(compute_network::<PrivacyDetails>(privacy, addr, prefix_len)),
            Err(rr) => Err(format!("{}", rr)),
        },
    }
}

#[cfg(not(test))]
pub fn get_ipinfo_company(addr: IpAddr) -> Result<(CompanyDetails, Option<IpNet>), String> {
    if !(*USE_IPINFO) {
        return Err("Ipinfo is not enabled. You can enable it by setting USE_IPINFO=true".to_string());
    }

    match IPINFO.deref() {
        Err(rr) => Err(format!("could not read city db: {}", rr)),
        Ok(ipinfo) => match ipinfo.company.lookup_prefix(addr) {
            Ok((comp, prefix_len)) => Ok(compute_network::<CompanyDetails>(comp, addr, prefix_len)),
            Err(rr) => Err(format!("{}", rr)),
        },
    }
}

#[cfg(not(test))]
pub fn get_ipinfo_asn(addr: IpAddr) -> Result<(AsnDetails, Option<IpNet>), String> {
    if !(*USE_IPINFO) {
        return Err("Ipinfo is not enabled. You can enable it by setting USE_IPINFO=true".to_string());
    }

    match IPINFO.deref() {
        Err(rr) => Err(format!("could not read asn db: {}", rr)),
        Ok(ipinfo) => match ipinfo.asn.lookup_prefix(addr) {
            Ok((asn, prefix_len)) => Ok(compute_network::<AsnDetails>(asn, addr, prefix_len)),
            Err(rr) => Err(format!("{}", rr)),
        },
    }
}

#[cfg(not(test))]
pub fn get_ipinfo_carrier(addr: IpAddr) -> Result<(CarrierDetails, Option<IpNet>), String> {
    if !(*USE_IPINFO) {
        return Err("Ipinfo is not enabled. You can enable it by setting USE_IPINFO=true".to_string());
    }

    match IPINFO.deref() {
        Err(rr) => Err(format!("could not read city db: {}", rr)),
        Ok(ipinfo) => match ipinfo.carrier.lookup_prefix(addr) {
            Ok((car, prefix_len)) => Ok(compute_network::<CarrierDetails>(car, addr, prefix_len)),
            Err(rr) => Err(format!("{}", rr)),
        },
    }
}

#[cfg(test)]
pub fn get_maxmind_country(_addr: IpAddr) -> Result<(Country<'static>, Option<IpNet>), String> {
    Err("TEST".into())
}

#[cfg(test)]
pub fn get_maxmind_asn(_addr: IpAddr) -> Result<(Asn<'static>, Option<IpNet>), String> {
    Err("TEST".into())
}

#[cfg(test)]
pub fn get_maxmind_city(_addr: IpAddr) -> Result<(City<'static>, Option<IpNet>), String> {
    Err("TEST".into())
}

#[cfg(test)]
pub fn get_ipinfo_location(_addr: IpAddr) -> Result<(LocationDetails, Option<IpNet>), String> {
    Err("TEST".into())
}

#[cfg(test)]
pub fn get_ipinfo_privacy(_addr: IpAddr) -> Result<(PrivacyDetails, Option<IpNet>), String> {
    Err("TEST".into())
}

#[cfg(test)]
pub fn get_ipinfo_company(_addr: IpAddr) -> Result<(CompanyDetails, Option<IpNet>), String> {
    Err("TEST".into())
}

#[cfg(test)]
pub fn get_ipinfo_asn(_addr: IpAddr) -> Result<(AsnDetails, Option<IpNet>), String> {
    Err("TEST".into())
}

#[cfg(test)]
pub fn get_ipinfo_carrier(_addr: IpAddr) -> Result<(CarrierDetails, Option<IpNet>), String> {
    Err("TEST".into())
}
