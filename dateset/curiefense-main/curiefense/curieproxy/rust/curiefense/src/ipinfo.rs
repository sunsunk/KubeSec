//! This file originated from ipinfo rust client api description. It was
//! modify to corespond to the datastructure from mmdb files instead of the web
//! api.
//!
//! see https://github.com/ipinfo/rust/blob/master/src/api.rs
//!
//! All data in the database are stored as string and must be parsed afterward.
//! This is why all field are represented as String.

use serde::{Deserialize, Serialize};

/// IP address lookup details.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LocationDetails {
    /// The city for the IP address.
    pub city: String,

    /// The country for the IP address.
    pub country: String,

    /// The latitude for the IP address. (f64)
    pub lat: String,

    /// The longitude for the IP address. (f64)
    pub lng: String,

    /// The region for the IP address.
    pub region: String,

    /// The region for the IP address.
    pub region_code: String,

    /// The postal code for the IP address.
    pub postal_code: Option<String>,

    /// The timezone for the IP address.
    pub timezone: Option<String>,
}

/// Privacy details.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PrivacyDetails {
    /// Whether this IP address belongs to a VPN. (bool)
    pub vpn: String,

    /// Whether this IP address belongs to a proxy. (bool)
    pub proxy: String,

    /// Whether this IP address is using Tor. (bool)
    pub tor: String,

    /// Whether this IP address is a relay. (bool)
    pub relay: String,

    /// Whether this IP address is from a hosting provider. (bool)
    pub hosting: String,

    /// The service offering the privacy service(s) listed here.
    pub service: String,
}

/// Company details.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CompanyDetails {
    // COMPANY
    /// The name of the entity that owns the IP address.
    pub name: String,

    /// The country (iso code) of the company that owns this IP address.
    pub country: String,

    /// The domain for the entity that owns this IP address.
    pub domain: String,

    /// The type of entity that owns this IP address. (i.e., business, education, hosting, isp)
    #[serde(rename = "type")]
    pub company_type: String,

    // AS
    /// The AS number. (format "AS{u32}")
    pub asn: String,

    /// The name of the entity that owns this AS.
    pub as_name: String,

    /// The domain for the entity that owns this AS.
    pub as_domain: String,

    /// The entity type that owns this AS. (i.e., business, education, hosting, isp)
    pub as_type: String,
}

/// ASN details.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AsnDetails {
    /// The AS number.
    pub asn: String,

    /// The name of the entity that owns this AS.
    pub name: String,

    /// The domain for the entity that owns this AS.
    pub domain: String,

    /// The route for this AS.
    pub route: String,

    /// The entity type that owns this AS. (i.e., business, education, hosting, isp)
    #[serde(rename = "type")]
    pub asn_type: String,
}

/// Mobile carrier details.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CarrierDetails {
    /// The name of the carrier ISP that owns that mobile IP address.
    pub carrier: String,

    /// The country code of the carrier ISP that owns that mobile IP address.
    #[serde(rename = "cc")]
    pub country_code: String,

    /// MCC GSM network code of this carrier.
    pub mcc: String,

    /// MNC GSM network code of this carrier.
    pub mnc: String,

    /// The network of the carrier ISP that owns that mobile IP address.
    pub network: String,
}
