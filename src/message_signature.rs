use std::collections::HashMap;

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use form_urlencoded;
use httpsig::prelude::{
    message_component::{
        DerivedComponentName, HttpMessageComponent, HttpMessageComponentId,
        HttpMessageComponentName, HttpMessageComponentParam,
    },
    AlgorithmName, HttpSigResult, HttpSignatureBase, HttpSignatureParams, SecretKey, SharedKey,
    SigningKey,
};
use reqwest::blocking::{Body as ReqwestBody, Request};
use reqwest::header::{HeaderName, HeaderValue};
use sfv::{Dictionary, Parser};
use sha2::{Digest, Sha256};
use url::Url;

use crate::utils::HeaderValueExt;

pub fn sign_request(request: &mut Request, key_material: &[u8]) -> Result<()> {
    let signature_input = ensure_signature_input(request, key_material)?;
    let entries = parse_signature_input(&signature_input)?;
    if entries.is_empty() {
        bail!("Signing requires at least one entry in Signature-Input");
    }

    let query_params = QueryParams::from_url(request.url());
    if entries
        .iter()
        .any(|(_, params)| contains_content_digest(&params.covered_components))
        && !request.headers().contains_key("content-digest")
    {
        insert_content_digest(request)?;
    }

    let mut signature_values = Vec::new();
    let mut signing_key: Option<MessageSigningKey> = None;
    let mut expected_alg: Option<String> = None;

    for (name, params) in entries {
        let alg = params
            .alg
            .as_deref()
            .ok_or_else(|| anyhow!("Signature parameters must include an alg value"))?
            .to_ascii_lowercase();
        let algorithm = algorithm_from_str(&alg)?;

        if let Some(existing) = expected_alg.as_ref() {
            if existing != &alg {
                bail!(
                    "All signatures must use the same algorithm (found both {existing} and {alg})"
                );
            }
        } else {
            expected_alg = Some(alg.clone());
            signing_key = Some(build_signing_key(key_material, algorithm, &alg)?);
        }

        let key = signing_key
            .as_ref()
            .expect("signing key should have been initialized");

        let components = build_component_lines(request, &params, &query_params)?;
        let signature_base = HttpSignatureBase::try_new(&components, &params)
            .context("Failed to build signature base")?;
        let headers = signature_base
            .build_signature_headers(key, Some(name.as_str()))
            .context("Failed to build signature headers")?;
        signature_values.push(headers.signature_header_value());
    }

    let header_value = signature_values.join(", ");
    request.headers_mut().insert(
        HeaderName::from_static("signature"),
        HeaderValue::from_str(&header_value)?,
    );
    Ok(())
}

fn ensure_signature_input(request: &mut Request, key_material: &[u8]) -> Result<String> {
    let mut fragments = Vec::new();
    let header_name = HeaderName::from_static("signature-input");
    for value in request.headers().get_all(&header_name).iter() {
        fragments.push(header_value_to_string(value)?);
    }
    if fragments.is_empty() {
        let alg = determine_alg_from_key(key_material);
        let mut value = String::from(r#"sig1=("@method" "@target-uri""#);
        if request.body().is_some() {
            value.push_str(r#" "content-digest""#);
        }
        value.push_str(r#")"#);
        value.push_str(&format!(r#";alg="{alg}""#));

        request
            .headers_mut()
            .insert(header_name, HeaderValue::from_str(&value)?);
        return Ok(value);
    }
    Ok(fragments.join(", "))
}

fn determine_alg_from_key(key_material: &[u8]) -> String {
    if let Ok(pem) = std::str::from_utf8(key_material) {
        if pem.contains("-----BEGIN") {
            if let Ok(secret) = SecretKey::from_pem(pem) {
                return secret.alg().as_str().to_string();
            }
        }
    }
    // Default to ed25519 as it's the most common modern default for raw keys
    "ed25519".to_string()
}

fn parse_signature_input(value: &str) -> Result<Vec<(String, HttpSignatureParams)>> {
    let dictionary: Dictionary = Parser::new(value)
        .parse()
        .context("Failed to parse Signature-Input header as Structured Field Values")?;
    let mut entries = Vec::new();
    for (name, entry) in dictionary.iter() {
        let params = HttpSignatureParams::try_from(entry)
            .with_context(|| format!("Failed to interpret {} in Signature-Input", name))?;
        entries.push((name.to_string(), params));
    }
    Ok(entries)
}

fn header_value_to_string(value: &HeaderValue) -> Result<String> {
    match value.to_ascii_or_latin1() {
        Ok(s) => Ok(s.to_string()),
        Err(bad) => Ok(bad.latin1()),
    }
}

fn algorithm_from_str(value: &str) -> Result<AlgorithmName> {
    match value {
        "ed25519" => Ok(AlgorithmName::Ed25519),
        "ecdsa-p256-sha256" => Ok(AlgorithmName::EcdsaP256Sha256),
        "ecdsa-p384-sha384" => Ok(AlgorithmName::EcdsaP384Sha384),
        "hmac-sha256" => Ok(AlgorithmName::HmacSha256),
        _ => bail!("Unsupported algorithm '{value}' in Signature-Input"),
    }
}

fn build_signing_key(
    key_material: &[u8],
    algorithm: AlgorithmName,
    alg_name: &str,
) -> Result<MessageSigningKey> {
    let text = std::str::from_utf8(key_material).ok();

    if let Some(pem) = text {
        if pem.contains("-----BEGIN") {
            let secret =
                SecretKey::from_pem(pem).context("Failed to parse private key PEM for signing")?;
            if secret.alg().as_str() != algorithm.as_str() {
                bail!(
                    "Key algorithm {} does not match signature parameters ({alg_name})",
                    secret.alg().as_str()
                );
            }
            return Ok(MessageSigningKey::Secret(secret));
        }
    }

    match algorithm {
        AlgorithmName::HmacSha256 => {
            let ascii = text.ok_or_else(|| {
                anyhow!("HMAC key material must be provided as ASCII/base64 text")
            })?;
            let shared_key = SharedKey::from_base64(ascii)
                .context("Failed to parse HMAC shared key as base64")?;
            Ok(MessageSigningKey::Shared(shared_key))
        }
        _ => {
            let bytes = if let Some(ascii) = text {
                let decoded = STANDARD
                    .decode(ascii.trim())
                    .context("Failed to base64-decode private key material")?;
                decoded
            } else {
                key_material.to_vec()
            };
            let secret = SecretKey::from_bytes(algorithm, &bytes)
                .context("Failed to parse private key bytes")?;
            Ok(MessageSigningKey::Secret(secret))
        }
    }
}

fn contains_content_digest(components: &[HttpMessageComponentId]) -> bool {
    components.iter().any(|component| match &component.name {
        HttpMessageComponentName::HttpField(field) => field.eq_ignore_ascii_case("content-digest"),
        _ => false,
    })
}

fn insert_content_digest(request: &mut Request) -> Result<()> {
    let bytes = buffer_request_body(request)?;
    let digest = Sha256::digest(&bytes);
    let value = format!("sha-256={}", STANDARD.encode(digest));
    request.headers_mut().insert(
        HeaderName::from_static("content-digest"),
        HeaderValue::from_str(&value)?,
    );
    Ok(())
}

fn buffer_request_body(request: &mut Request) -> Result<Vec<u8>> {
    if let Some(body) = request.body_mut() {
        let bytes = body
            .buffer()
            .context("Failed to buffer request body for Content-Digest")?
            .to_vec();
        *body = ReqwestBody::from(bytes.clone());
        Ok(bytes)
    } else {
        Ok(Vec::new())
    }
}

fn build_component_lines(
    request: &Request,
    params: &HttpSignatureParams,
    query_params: &QueryParams,
) -> Result<Vec<HttpMessageComponent>> {
    let mut components = Vec::new();
    for component_id in &params.covered_components {
        let values = gather_component_values(request, component_id, query_params)?;
        components.push(
            HttpMessageComponent::try_from((component_id, values.as_slice()))
                .context("Failed to build HTTP message component")?,
        );
    }
    Ok(components)
}

fn gather_component_values(
    request: &Request,
    component_id: &HttpMessageComponentId,
    query_params: &QueryParams,
) -> Result<Vec<String>> {
    match &component_id.name {
        HttpMessageComponentName::Derived(derived) => {
            gather_derived_component_values(request, derived, component_id, query_params)
        }
        HttpMessageComponentName::HttpField(field) => gather_http_field_values(request, field),
    }
}

fn gather_http_field_values(request: &Request, field: &str) -> Result<Vec<String>> {
    let name = field.to_ascii_lowercase();
    let header_name = HeaderName::from_bytes(name.as_bytes())
        .with_context(|| format!("Invalid header name in Signature-Input: {field}"))?;
    let values = request.headers().get_all(&header_name);
    if values.iter().next().is_none() {
        bail!("Signature-Input refers to header '{field}', but the request does not include it");
    }
    let mut collected = Vec::new();
    for value in values.iter() {
        collected.push(header_value_to_string(value)?);
    }
    Ok(collected)
}

fn gather_derived_component_values(
    request: &Request,
    derived: &DerivedComponentName,
    component_id: &HttpMessageComponentId,
    query_params: &QueryParams,
) -> Result<Vec<String>> {
    let url = request.url();
    match derived {
        DerivedComponentName::Method => Ok(vec![request.method().as_str().to_string()]),
        DerivedComponentName::TargetUri => Ok(vec![url.as_str().to_string()]),
        DerivedComponentName::Authority => Ok(vec![compute_authority(url)]),
        DerivedComponentName::Scheme => Ok(vec![url.scheme().to_ascii_lowercase()]),
        DerivedComponentName::RequestTarget => Ok(vec![compute_request_target(request)]),
        DerivedComponentName::Path => Ok(vec![compute_path(url)]),
        DerivedComponentName::Query => Ok(vec![compute_query(url)]),
        DerivedComponentName::QueryParam => gather_query_param_values(query_params, component_id),
        DerivedComponentName::SignatureParams => {
            bail!("@signature-params must not be included as a covered component");
        }
        DerivedComponentName::Status => {
            bail!("@status derived component is only valid in responses");
        }
    }
}

fn compute_authority(url: &Url) -> String {
    let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
    if let Some(port) = url.port() {
        if Some(port) != default_port_for_scheme(url.scheme()) {
            return format!("{host}:{port}");
        }
    }
    host
}

fn default_port_for_scheme(scheme: &str) -> Option<u16> {
    match scheme {
        "http" => Some(80),
        "https" => Some(443),
        _ => None,
    }
}

fn compute_request_target(request: &Request) -> String {
    if request.method() == reqwest::Method::CONNECT {
        let url = request.url();
        return compute_authority(url);
    }
    let url = request.url();
    let mut target = url.path().to_string();
    if let Some(query) = url.query() {
        target.push('?');
        target.push_str(query);
    }
    target
}

fn compute_path(url: &Url) -> String {
    let path = url.path();
    if path.is_empty() {
        "/".to_string()
    } else {
        path.to_string()
    }
}

fn compute_query(url: &Url) -> String {
    match url.query() {
        Some(q) => format!("?{q}"),
        None => "?".to_string(),
    }
}

fn gather_query_param_values(
    query_params: &QueryParams,
    component_id: &HttpMessageComponentId,
) -> Result<Vec<String>> {
    let name = component_id
        .params
        .0
        .iter()
        .find_map(|param| match param {
            HttpMessageComponentParam::Name(name) => Some(name.as_str()),
            _ => None,
        })
        .ok_or_else(|| anyhow!("@query-param requires a name parameter"))?;

    match query_params.counts.get(name) {
        Some(0) | None => bail!("Query parameter '{name}' is not present"),
        Some(2..) => bail!("Query parameter '{name}' occurs multiple times, which is unsupported"),
        _ => {}
    }

    let mut values = Vec::new();
    for entry in &query_params.entries {
        if entry.decoded_name == name {
            values.push(format!("{}={}", entry.encoded_name, entry.encoded_value));
        }
    }
    if values.is_empty() {
        bail!("Query parameter '{name}' is not present");
    }
    Ok(values)
}

struct QueryParams {
    entries: Vec<QueryParamEntry>,
    counts: HashMap<String, usize>,
}

struct QueryParamEntry {
    decoded_name: String,
    encoded_name: String,
    encoded_value: String,
}

impl QueryParams {
    fn from_url(url: &Url) -> Self {
        let mut counts = HashMap::new();
        let mut entries = Vec::new();
        if let Some(query) = url.query() {
            for (name, value) in form_urlencoded::parse(query.as_bytes()) {
                let decoded_name = name.into_owned();
                let decoded_value = value.into_owned();
                let encoded_name = encode_form_value(&decoded_name);
                let encoded_value = encode_form_value(&decoded_value);
                *counts.entry(decoded_name.clone()).or_insert(0) += 1;
                entries.push(QueryParamEntry {
                    decoded_name,
                    encoded_name,
                    encoded_value,
                });
            }
        }
        QueryParams { entries, counts }
    }
}

fn encode_form_value(value: &str) -> String {
    form_urlencoded::byte_serialize(value.as_bytes())
        .collect::<String>()
        .replace('+', "%20")
}

enum MessageSigningKey {
    Secret(SecretKey),
    Shared(SharedKey),
}

impl SigningKey for MessageSigningKey {
    fn sign(&self, data: &[u8]) -> HttpSigResult<Vec<u8>> {
        match self {
            MessageSigningKey::Secret(inner) => inner.sign(data),
            MessageSigningKey::Shared(inner) => inner.sign(data),
        }
    }

    fn key_id(&self) -> String {
        match self {
            MessageSigningKey::Secret(inner) => inner.key_id(),
            MessageSigningKey::Shared(inner) => inner.key_id(),
        }
    }

    fn alg(&self) -> AlgorithmName {
        match self {
            MessageSigningKey::Secret(inner) => inner.alg(),
            MessageSigningKey::Shared(inner) => inner.alg(),
        }
    }
}
