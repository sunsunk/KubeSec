/// body parsing functions
///
/// This module contains body parsing for the following mime types:
///
///  * json
///  * xml
///  * multipart/form-data
///  * urlencoded forms
///
/// The main function, parse_body, is the only exported function.
///
use multipart::server::Multipart;
use serde_json::Value;
use std::io::Read;
use xmlparser::{ElementEnd, EntityDefinition, ExternalId, Token};

use crate::config::raw::ContentType;
use crate::interface::Location;
use crate::logs::Logs;
use crate::requestfields::RequestField;
use crate::utils::decoders::parse_urlencoded_params_bytes;
use crate::utils::BodyProblem;
use jsonpath_rust::JsonPathFinder;
use lazy_static::lazy_static;
use regex::Regex;

mod graphql;

fn json_path(prefix: &[String]) -> String {
    if prefix.is_empty() {
        "JSON_ROOT".to_string()
    } else {
        prefix.join("_")
    }
}

lazy_static! {
    static ref GRAPHQL_REGEX: Regex =
        Regex::new(r#""\s?:\s?"\s?((?:query|mutation|subscription|fragment)\s[^"]*)(?:}?(?:\n)?"),?"#).unwrap();
}

/// flatten a JSON tree into the RequestField key/value store
/// key values are build by joining all path names with "_", where path names are:
///   * keys for objects ;
///   * indices for lists.
///
/// Scalar values are converted to string, with lowercase booleans and null values.
fn flatten_json(
    depth_budget: usize,
    args: &mut RequestField,
    prefix: &mut Vec<String>,
    value: Value,
) -> Result<(), ()> {
    if depth_budget == 0 {
        return Err(());
    }
    match value {
        Value::Array(array) => {
            prefix.push(String::new());
            let idx = prefix.len() - 1;
            for (i, v) in array.into_iter().enumerate() {
                prefix[idx] = format!("{}", i);
                flatten_json(depth_budget - 1, args, prefix, v)?;
            }
            prefix.pop();
        }
        Value::Object(mp) => {
            prefix.push(String::new());
            let idx = prefix.len() - 1;
            for (k, v) in mp.into_iter() {
                prefix[idx] = k;
                flatten_json(depth_budget - 1, args, prefix, v)?;
            }
            prefix.pop();
        }
        Value::String(str) => {
            args.add(json_path(prefix), Location::Body, str);
        }
        Value::Bool(b) => {
            args.add(
                json_path(prefix),
                Location::Body,
                (if b { "true" } else { "false" }).to_string(),
            );
        }
        Value::Number(n) => {
            args.add(json_path(prefix), Location::Body, format!("{}", n));
        }
        Value::Null => {
            args.add(json_path(prefix), Location::Body, "null".to_string());
        }
    }
    Ok(())
}

/// This should work with a stream of json items, not deserialize all at once
///
/// I tried qjsonrs, but it was approximatively 10x slower for small maps (but faster with larger maps)
/// qjronsrs -> serde_json benches:
///  * map/1 -> -98.83%
///  * map/100 -> -43.516%
///  * map/10000 -> +33.534%
///
/// next idea: adapting https://github.com/Geal/nom/blob/master/examples/json_iterator.rs
fn json_body(mxdepth: usize, args: &mut RequestField, body: &[u8]) -> Result<(), BodyProblem> {
    let value: Value = serde_json::from_slice(body).map_err(|rr| BodyProblem::DecodingError(rr.to_string(), None))?;

    let mut prefix = Vec::new();
    flatten_json(mxdepth, args, &mut prefix, value).map_err(|()| BodyProblem::TooDeep)
}

/// builds the XML path for a given stack, by appending key names with their indices
fn xml_path(stack: &[(String, u64)]) -> String {
    let mut out = String::new();
    for (s, i) in stack {
        out += s;
        // if i == 0, this means we are working with xml attributes
        if *i > 0 {
            out.extend(format!("{}", i).chars());
        }
    }
    out
}

/// pop the stack and checks for errors when closing an element
fn close_xml_element(
    args: &mut RequestField,
    stack: &mut Vec<(String, u64)>,
    close_name: Option<&str>,
) -> Result<(), String> {
    match stack.pop() {
        None => Err(format!("Invalid XML, extraneous element end: {:?}", close_name)),
        Some((openname, idx)) => {
            if let Some(local) = close_name {
                if openname != local {
                    return Err(format!(
                        "Invalid XML, wrong closing element. Expected: {}, got {}",
                        openname, local
                    ));
                }
            }
            if idx == 0 {
                // empty XML element, save it with an empty string
                let path = xml_path(stack) + openname.as_str() + "1";
                args.add(path, Location::Body, String::new());
            }
            Ok(())
        }
    }
}

fn xml_increment_last(stack: &mut [(String, u64)]) -> u64 {
    if let Some(curtop) = stack.last_mut() {
        let prev = curtop.1;
        curtop.1 = prev + 1;
        return prev;
    }
    0
}

fn xml_external_id(args: &mut RequestField, stack: &[(String, u64)], name: &str, me: Option<ExternalId>) {
    match me {
        Some(ExternalId::System(spn)) => {
            let path = xml_path(stack) + "entity/" + name;
            args.add(path, Location::Body, "SYSTEM ".to_string() + spn.as_str());
            let path_raw = xml_path(stack) + "entity_raw/" + name;
            args.add(
                path_raw,
                Location::Body,
                "<!DOCTYPE ".to_string() + name + " SYSTEM \"" + spn.as_str() + "\"",
            );
        }
        Some(ExternalId::Public(spn1, spn2)) => {
            let path = xml_path(stack) + "entity/" + name;
            args.add(
                path,
                Location::Body,
                "PUBLIC ".to_string() + spn1.as_str() + " " + spn2.as_str(),
            );
            let path_raw = xml_path(stack) + "entity_raw/" + name;
            args.add(
                path_raw,
                Location::Body,
                "<!DOCTYPE ".to_string() + name + " PUBLIC \"" + spn1.as_str() + "\" \"" + spn2.as_str() + "\"",
            );
        }
        None => (),
    }
}

/// Parses the XML body by iterating on the token stream
///
/// This checks the following errors, in addition to the what the lexer gets:
///   * mismatched opening and closing tags
///   * premature end of document
fn xml_body(mxdepth: usize, args: &mut RequestField, body: &[u8]) -> Result<(), BodyProblem> {
    let body_utf8 = String::from_utf8_lossy(body);
    let mut stack: Vec<(String, u64)> = Vec::new();
    for rtoken in xmlparser::Tokenizer::from(body_utf8.as_ref()) {
        if stack.len() >= mxdepth {
            return Err(BodyProblem::TooDeep);
        }
        let token = rtoken.map_err(|rr| BodyProblem::DecodingError(rr.to_string(), None))?;
        match token {
            Token::ProcessingInstruction { .. } => (),
            Token::Comment { .. } => (),
            Token::Declaration { .. } => (),
            Token::DtdStart { external_id, name, .. } => xml_external_id(args, &stack, name.as_str(), external_id),
            Token::DtdEnd { .. } => (),
            Token::EmptyDtd { external_id, name, .. } => xml_external_id(args, &stack, name.as_str(), external_id),
            Token::EntityDeclaration { name, definition, .. } => match definition {
                EntityDefinition::EntityValue(span) => args.add(
                    "_XMLENTITY_VALUE_".to_string() + name.as_str(),
                    Location::Body,
                    span.to_string(),
                ),
                EntityDefinition::ExternalId(eid) => xml_external_id(args, &stack, "entity", Some(eid)),
            },
            Token::ElementStart { local, .. } => {
                // increment element index for the current element
                xml_increment_last(&mut stack);
                // and push the new element
                stack.push((local.to_string(), 0))
            }
            Token::ElementEnd { end, .. } => match end {
                //  <foo/>
                ElementEnd::Empty => {
                    close_xml_element(args, &mut stack, None).map_err(|r| BodyProblem::DecodingError(r, None))?
                }
                //  <foo>
                ElementEnd::Open => (),
                //  </foo>
                ElementEnd::Close(_, local) => close_xml_element(args, &mut stack, Some(local.as_str()))
                    .map_err(|r| BodyProblem::DecodingError(r, None))?,
            },
            Token::Attribute { local, value, .. } => {
                let path = xml_path(&stack) + local.as_str();
                args.add(path, Location::Body, value.to_string());
            }
            Token::Text { text } => {
                let trimmed = text.trim();
                if !trimmed.is_empty() {
                    xml_increment_last(&mut stack);
                    args.add(xml_path(&stack), Location::Body, trimmed.to_string());
                }
            }
            Token::Cdata { text, .. } => {
                xml_increment_last(&mut stack);
                args.add(xml_path(&stack), Location::Body, text.to_string());
            }
        }
    }
    if stack.is_empty() {
        Ok(())
    } else {
        Err(BodyProblem::DecodingError(
            "XML error: premature end of document".to_string(),
            None,
        ))
    }
}

/// parses bodies that are url encoded forms, like query params
fn forms_body(args: &mut RequestField, body: &[u8]) -> Result<(), BodyProblem> {
    // TODO: body is traversed twice here, this is inefficient
    if body.contains(&b'=') && body.iter().all(|x| *x > 0x20 && *x < 0x7f) {
        parse_urlencoded_params_bytes(args, body, Location::BodyArgumentValue);
        Ok(())
    } else {
        Err(BodyProblem::DecodingError(
            "Body is not forms encoded".to_string(),
            Some("forms-encoded body".to_string()),
        ))
    }
}

/// reuses the multipart crate to parse these bodies
///
/// will not work properly with binary data
fn multipart_form_encoded(boundary: &str, args: &mut RequestField, body: &[u8]) -> Result<(), BodyProblem> {
    let mut multipart = Multipart::with_body(body, boundary);
    multipart
        .foreach_entry(|mut entry| {
            let mut content = Vec::new();
            let _ = entry.data.read_to_end(&mut content);
            let name = entry.headers.name.to_string();
            let scontent = String::from_utf8_lossy(&content);
            args.add(name, Location::Body, scontent.to_string());
        })
        .map_err(|rr| BodyProblem::DecodingError(rr.to_string(), None))
}

///try to parse a list of graphql queries
fn parse_graphql_array(
    matches: Vec<&str>,
    max_depth: usize,
    args: &mut RequestField,
    logs: &mut Logs,
) -> Result<(), BodyProblem> {
    let mut graphql_res = Ok(());
    for item in matches.iter() {
        graphql_res = graphql::graphql_body_str(max_depth, args, &item);
        if graphql_res.is_err() {
            logs.debug(|| format!("error while parsing with graphql:  {:?}", graphql_res));
            return graphql_res;
        }
    }
    return graphql_res;
}

/// body parsing function, returns an error when the body can't be decoded
pub fn parse_body(
    logs: &mut Logs,
    args: &mut RequestField,
    max_depth: usize,
    mcontent_type: Option<&str>,
    accepted_types: &[ContentType],
    graphql_path: &str,
    body: &[u8],
) -> Result<(), BodyProblem> {
    logs.debug("body parsing started");
    if max_depth == 0 {
        logs.warning("max_depth is 0, body parsing avoided");
        return Ok(());
    }

    let active_accepted_types = if accepted_types.is_empty() {
        &ContentType::VALUES
    } else {
        accepted_types
    };

    if let Some(content_type) = mcontent_type {
        for t in active_accepted_types {
            match t {
                ContentType::Graphql => {
                    if content_type == "application/graphql" {
                        return graphql::graphql_body(max_depth, args, body);
                    }
                }
                ContentType::Json => {
                    if content_type.ends_with("/json") {
                        let json_body_res = json_body(max_depth, args, body);
                        if let Ok(res) = json_body_res {
                            //result of string body
                            let body_json_str = std::str::from_utf8(body)
                                .map_err(|rr| BodyProblem::DecodingError(rr.to_string(), None))?;
                            // use default regex - if has no graphql_path (jsonpath filter)
                            if graphql_path.is_empty() {
                                let mut matches: Vec<String> = Vec::new();
                                for capture in GRAPHQL_REGEX.captures_iter(body_json_str) {
                                    if let Some(m) = capture.get(1) {
                                        let matched_str = m.as_str().replace("\\n", "\n");
                                        matches.push(matched_str);
                                    }
                                }
                                let matches_vec: Vec<&str> = matches.iter().map(|s| s.as_str()).collect();
                                if !matches_vec.is_empty() {
                                    return parse_graphql_array(matches_vec, max_depth, args, logs);
                                }
                                //else - there are no graphql matches, return original json_body_res
                            } else {
                                match JsonPathFinder::from_str(body_json_str, graphql_path) {
                                    Ok(finder) => {
                                        let found_queries = finder.find();
                                        if let Value::Array(arr) = found_queries {
                                            let matches: Vec<&str> = arr.iter().filter_map(|v| v.as_str()).collect();
                                            return parse_graphql_array(matches, max_depth, args, logs);
                                        }
                                        //else (it's not an array) - there are no graphql matches, return original json_body_res
                                    }
                                    Err(e) => logs.debug(|| format!("error while parsing with jsonpath: {}", e)),
                                }
                            }
                        }
                        //regular /json body
                        return json_body_res;
                    }
                }
                ContentType::MultipartForm => {
                    if let Some(boundary) = content_type.strip_prefix("multipart/form-data; boundary=") {
                        return multipart_form_encoded(boundary, args, body);
                    }
                }
                ContentType::Xml => {
                    if content_type.ends_with("/xml") {
                        return xml_body(max_depth, args, body);
                    }
                }
                ContentType::UrlEncoded => {
                    if content_type == "application/x-www-form-urlencoded" {
                        return forms_body(args, body);
                    }
                }
            }
        }
    }

    logs.debug("content-type based body parsing failed");

    // content-type not found
    if accepted_types.is_empty() {
        // we had no particular expection, so blindly try json, and urlencoded
        json_body(max_depth, args, body).or_else(|_| forms_body(args, body))
    } else {
        // we expected a specific content type!
        Err(BodyProblem::DecodingError(
            match mcontent_type {
                None => "no content type specified".to_string(),
                Some(content_type) => format!("content type is {}", content_type),
            },
            Some(format!("{:?}", accepted_types)),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::contentfilter::Transformation;
    use crate::logs::LogLevel;

    fn test_parse_ok_dec(
        dec: &[Transformation],
        mcontent_type: Option<&str>,
        accepted_types: &[ContentType],
        body: &[u8],
        max_depth: usize,
    ) -> RequestField {
        let mut logs = Logs::default();
        let mut args = RequestField::new(dec);
        parse_body(&mut logs, &mut args, max_depth, mcontent_type, accepted_types, "", body).unwrap();
        for lg in logs.logs {
            if lg.level > LogLevel::Debug {
                panic!("unexpected log: {:?}", lg);
            }
        }
        args
    }

    fn test_parse_bad(mcontent_type: Option<&str>, accepted_types: &[ContentType], body: &[u8], max_depth: usize) {
        let mut logs = Logs::default();
        let mut args = RequestField::new(&[]);
        assert!(parse_body(&mut logs, &mut args, max_depth, mcontent_type, accepted_types, "", body).is_err());
    }

    fn test_parse_dec(
        dec: &[Transformation],
        mcontent_type: Option<&str>,
        accepted_types: &[ContentType],
        body: &[u8],
        expected: &[(&str, &str)],
    ) {
        let args = test_parse_ok_dec(dec, mcontent_type, accepted_types, body, 500);
        for (k, v) in expected {
            match args.get_str(k) {
                None => panic!("Argument not set {}", k),
                Some(actual) => assert_eq!(actual, *v),
            }
        }
        if args.len() != expected.len() {
            println!("Spurious arguments:");
            for (k, v) in args.iter() {
                if !expected.iter().any(|(ek, _)| ek == &k) {
                    println!(" ({:?}, {:?}),", k, v);
                }
            }
            panic!("Spurious arguments");
        }
    }

    fn test_parse(mcontent_type: Option<&str>, body: &[u8], expected: &[(&str, &str)]) {
        test_parse_dec(&[], mcontent_type, &[], body, expected)
    }

    #[test]
    fn json_empty_body() {
        test_parse(Some("application/json"), br#"{}"#, &[]);
    }

    #[test]
    fn json_scalar() {
        test_parse(Some("application/json"), br#""scalar""#, &[("JSON_ROOT", "scalar")]);
    }

    #[test]
    fn json_scalar_b64() {
        test_parse_dec(
            &[Transformation::Base64Decode],
            Some("application/json"),
            &[],
            br#""c2NhbGFyIQ==""#,
            &[("JSON_ROOT", "c2NhbGFyIQ=="), ("JSON_ROOT:decoded", "scalar!")],
        );
    }

    #[test]
    fn json_simple_object() {
        test_parse(
            Some("application/json"),
            br#"{"a": "b", "c": "d"}"#,
            &[("a", "b"), ("c", "d")],
        );
    }

    #[test]
    fn json_bad() {
        test_parse_bad(Some("application/json"), &[], br#"{"a": "b""#, 500);
    }

    #[test]
    fn json_collision() {
        test_parse(
            Some("application/json"),
            br#"{"a": {"b": "1"}, "a_b": "2"}"#,
            &[("a_b", "1 2")],
        );
    }

    #[test]
    fn json_simple_array() {
        test_parse(Some("application/json"), br#"["a", "b"]"#, &[("0", "a"), ("1", "b")]);
    }

    #[test]
    fn json_nested_objects() {
        test_parse(
            Some("application/json"),
            br#"{"a": [true,null,{"z": 0.2}], "c": {"d": 12}}"#,
            &[("a_0", "true"), ("a_1", "null"), ("a_2_z", "0.2"), ("c_d", "12")],
        );
    }

    #[test]
    fn arguments_collision() {
        let mut logs = Logs::default();
        let mut args = RequestField::new(&[]);
        args.add("a".to_string(), Location::Body, "query_arg".to_string());
        parse_body(
            &mut logs,
            &mut args,
            500,
            Some("application/json"),
            &[],
            "",
            br#"{"a": "body_arg"}"#,
        )
        .unwrap();
        assert_eq!(args.get_str("a"), Some("query_arg body_arg"));
    }

    #[test]
    fn xml_simple() {
        test_parse(Some("text/xml"), br#"<a>content</a>"#, &[("a1", "content")]);
    }

    #[test]
    fn xml_simple_b64() {
        test_parse_dec(
            &[Transformation::Base64Decode],
            Some("text/xml"),
            &[],
            br#"<a>ZHFzcXNkcXNk</a>"#,
            &[("a1", "ZHFzcXNkcXNk"), ("a1:decoded", "dqsqsdqsd")],
        );
    }

    #[test]
    fn xml_simple_html() {
        test_parse_dec(
            &[Transformation::HtmlEntitiesDecode],
            Some("text/xml"),
            &[],
            br#"<a>&lt;em&gt;</a>"#,
            &[("a1", "<em>")],
        );
    }

    #[test]
    fn xml_simple_html_partial() {
        test_parse_dec(
            &[Transformation::HtmlEntitiesDecode],
            Some("text/xml"),
            &[],
            br#"<a>&lt;em&gt</a>"#,
            &[("a1", "<em&gt")],
        );
    }

    #[test]
    fn xml_bad1() {
        test_parse_bad(Some("text/xml"), &[], br#"<a>"#, 500);
    }

    #[test]
    fn xml_bad2() {
        test_parse_bad(Some("text/xml"), &[], br#"<a>x</b>"#, 500);
    }

    #[test]
    fn xml_bad3() {
        test_parse_bad(Some("text/xml"), &[], br#"<a 1x="12">x</a>"#, 500);
    }

    #[test]
    fn xml_nested() {
        test_parse(
            Some("text/xml"),
            br#"<a>a<b foo="bar">xxx</b>z</a>"#,
            &[("a1", "a"), ("a3", "z"), ("a2bfoo", "bar"), ("a2b1", "xxx")],
        );
    }

    #[test]
    fn xml_cdata() {
        test_parse(
            Some("text/xml"),
            br#"<a ><![CDATA[ <script>alert("test");</script> ]]></a >"#,
            &[("a1", r#" <script>alert("test");</script> "#)],
        );
    }

    #[test]
    fn xml_nested_empty() {
        test_parse(Some("text/xml"), br#"<a><b><c></c></b></a>"#, &[("a1b1c1", "")]);
    }

    #[test]
    fn xml_nested_empty_b() {
        test_parse(
            Some("application/xml"),
            br#"<a> <b> <c> </c></b></a>"#,
            &[("a1b1c1", "")],
        );
    }

    #[test]
    fn xml_entity_a() {
        test_parse(
            Some("application/xml"),
            br#"<!DOCTYPE foo [ <!ENTITY myentity "my entity value" > ]><a>xx</a>"#,
            &[("a1", "xx"), ("_XMLENTITY_VALUE_myentity", "my entity value")],
        );
    }

    #[test]
    fn xml_entity_b() {
        test_parse(
            Some("application/xml"),
            br#"<!DOCTYPE foo [ <!ENTITY ext SYSTEM "http://website.com" > ]><a>xx</a>"#,
            &[
                ("a1", "xx"),
                ("entity_raw/entity", "<!DOCTYPE entity SYSTEM \"http://website.com\""),
                ("entity/entity", "SYSTEM http://website.com"),
            ],
        );
    }

    #[test]
    fn xml_spaces() {
        test_parse(
            Some("text/xml"),
            br#"<a>a <b><c> c </c>  </b>  </a>"#,
            &[("a1", "a"), ("a2b1c1", "c")],
        );
    }

    #[test]
    fn xml_space_in_attribute() {
        test_parse(
            Some("application/xml"),
            br#"<a foo1=" ab c "><foo>abc</foo></a>"#,
            &[("afoo1", " ab c "), ("a1foo1", "abc")],
        );
    }

    #[test]
    fn xml_indent() {
        test_parse(
            Some("text/xml"),
            br#"
    <a>x1
      <b>x2</b>
    </a>
    "#,
            &[("a1", "x1"), ("a2b1", "x2")],
        );
    }

    #[test]
    fn xml_indent_too_deep() {
        test_parse_bad(Some("text/xml"), &[], br#"<a>x1<b>x2</b></a>"#, 2);
    }

    #[test]
    fn xml_indent_depth_ok() {
        test_parse_ok_dec(&[], Some("text/xml"), &[], br#"<a>x1<b>x2</b></a>"#, 3);
    }

    #[test]
    fn multipart() {
        let content = [
            "--------------------------28137e3917e320b3",
            "Content-Disposition: form-data; name=\"foo\"",
            "",
            "bar",
            "--------------------------28137e3917e320b3",
            "Content-Disposition: form-data; name=\"baz\"",
            "",
            "qux",
            "--------------------------28137e3917e320b3--",
            "",
        ];
        test_parse(
            Some("multipart/form-data; boundary=------------------------28137e3917e320b3"),
            content.join("\r\n").as_bytes(),
            &[("foo", "bar"), ("baz", "qux")],
        );
    }

    #[test]
    fn urlencoded() {
        test_parse(
            Some("application/x-www-form-urlencoded"),
            b"a=1&b=2&c=3",
            &[("a", "1"), ("b", "2"), ("c", "3")],
        );
    }

    #[test]
    fn urlencoded_default() {
        test_parse(None, b"a=1&b=2&c=3", &[("a", "1"), ("b", "2"), ("c", "3")]);
    }

    #[test]
    fn json_default() {
        test_parse(None, br#"{"a": "b", "c": "d"}"#, &[("a", "b"), ("c", "d")]);
    }

    #[test]
    fn json_but_expect_json_ct() {
        test_parse_dec(
            &[],
            Some("application/json"),
            &[ContentType::Json],
            br#"{"a": "b", "c": "d"}"#,
            &[("a", "b"), ("c", "d")],
        );
    }

    #[test]
    fn json_but_expect_json_noct() {
        test_parse_bad(None, &[ContentType::Json], br#"{"a": "b", "c": "d"}"#, 500);
    }

    #[test]
    fn json_but_expect_xml_ct() {
        test_parse_bad(Some("text/xml"), &[ContentType::Json], br#"{"a": "b", "c": "d"}"#, 500);
    }

    #[test]
    fn json_but_expect_xml_noct() {
        test_parse_bad(None, &[ContentType::Json], br#"{"a": "b", "c": "d"}"#, 500);
    }

    #[test]
    fn json_but_expect_json_xml_ct() {
        test_parse_dec(
            &[],
            Some("application/json"),
            &[ContentType::Xml, ContentType::Json],
            br#"{"a": "b", "c": "d"}"#,
            &[("a", "b"), ("c", "d")],
        );
    }

    #[test]
    fn graphql_simple() {
        test_parse_dec(
            &[],
            Some("application/graphql"),
            &[ContentType::Graphql],
            br#"{ hero { name } }"#,
            &[("gdir-s0-hero-s0", "name")],
        );
    }

    #[test]
    fn graphql_alias() {
        test_parse_dec(
            &[],
            Some("application/graphql"),
            &[ContentType::Graphql],
            br#"{ empireHero: hero(episode: EMPIRE) { name } jediHero: hero(episode: JEDI) { name } }"#,
            &[
                ("gdir-s0-hero-episode", "EMPIRE"),
                ("gdir-s1-hero-episode", "JEDI"),
                ("gdir-s0-hero-s0", "name"),
                ("gdir-s0-hero-alias", "empireHero"),
                ("gdir-s1-hero-alias", "jediHero"),
                ("gdir-s1-hero-s0", "name"),
            ],
        );
    }

    #[test]
    fn graphql_fragvars() {
        test_parse_dec(
            &[],
            Some("application/graphql"),
            &[ContentType::Graphql],
            br#"query HeroComparison($first: Int = 3) {
                leftComparison: hero(episode: EMPIRE) {
                  ...comparisonFields
                }
                rightComparison: hero(episode: JEDI) {
                  ...comparisonFields
                }
              }
              
              fragment comparisonFields on Character {
                name
                friendsConnection(first: $first) {
                  totalCount
                  edges {
                    node {
                      name
                    }
                  }
                }
              }"#,
            &[
                ("gdir-HeroComparison-s1-hero-alias", "rightComparison"),
                ("gdir-HeroComparison-s0-hero-s0-frag", "comparisonFields"),
                ("gfrag-comparisonFields-s1-friendsConnection-first", "$first"),
                ("gfrag-comparisonFields-s1-friendsConnection-s0", "totalCount"),
                ("gdir-HeroComparison-s0-hero-alias", "leftComparison"),
                ("gdir-HeroComparison-s0-hero-episode", "EMPIRE"),
                ("gdir-HeroComparison-s1-hero-episode", "JEDI"),
                ("gfrag-comparisonFields-s0", "name"),
                (
                    "gfrag-comparisonFields-s1-friendsConnection-s1-edges-s0-node-s0",
                    "name",
                ),
                ("gdir-HeroComparison-first-defvalue", "3"),
                ("gdir-HeroComparison-s1-hero-s0-frag", "comparisonFields"),
            ],
        );
    }

    #[test]
    fn graphql_dump_schema() {
        test_parse_dec(
            &[],
            Some("application/graphql"),
            &[ContentType::Graphql],
            br#"{ __schema { types { name } } }"#,
            &[("gdir-s0-__schema-s0-types-s0", "name")],
        );
    }

    #[test]
    fn graphql_sqli() {
        test_parse_dec(
            &[],
            Some("application/graphql"),
            &[ContentType::Graphql],
            br#"{ login( input:{user:"admin" password:"password' or 1=1 -- -"}) { success jwt } }"#,
            &[
                ("gdir-s0-login-s1", "jwt"),
                ("gdir-s0-login-s0", "success"),
                (
                    "gdir-s0-login-input",
                    "{user: \"admin\",password: \"password' or 1=1 -- -\"}",
                ),
            ],
        );
    }

    #[test]
    fn graphql_userselect() {
        test_parse_dec(
            &[],
            Some("application/graphql"),
            &[ContentType::Graphql],
            br#"query {
                allUsers(id: 1337) {
                  name
                }
              }"#,
            &[("gdir-s0-allUsers-id", "1337"), ("gdir-s0-allUsers-s0", "name")],
        );
    }

    #[test]
    fn graphql_too_much_nesting() {
        test_parse_bad(
            Some("application/graphql"),
            &[ContentType::Graphql],
            br#"query {
                allUsers(id: 1337) {
                  name
                }
              }"#,
            2,
        );
    }

    #[test]
    fn json_indent_too_deep_array() {
        test_parse_bad(Some("application/json"), &[], br#"[["a"]]"#, 2);
    }

    #[test]
    fn json_indent_too_deep_dict() {
        test_parse_bad(Some("application/json"), &[], br#"{"k":{"v":"a"}}"#, 2);
    }

    #[test]
    fn json_indent_depth_ok() {
        test_parse_ok_dec(&[], Some("application/json"), &[], br#"[["a"]]"#, 3);
    }

    #[test]
    fn urlencoded_depth_0() {
        let mut logs = Logs::default();
        let mut args = RequestField::new(&[]);
        parse_body(
            &mut logs,
            &mut args,
            0,
            Some("application/x-www-form-urlencoded"),
            &[],
            "",
            b"a=1&b=2&c=3",
        )
        .unwrap();
        assert!(args.is_empty())
    }
}
