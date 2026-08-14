// Thin Microsoft Graph API HTTP client.
//
// All requests go through extism's host HTTP facility — no reqwest or hyper,
// both of which are incompatible with wasm32-unknown-unknown.

use extism_pdk::{http, HttpRequest};
use serde_json::Value;

pub struct GraphClient {
    token: String,
    base_url: String,
}

impl GraphClient {
    pub fn new(token: String) -> Self {
        Self {
            token,
            base_url: "https://graph.microsoft.com/v1.0".to_string(),
        }
    }

    pub fn with_base_url(token: String, base_url: String) -> Self {
        Self { token, base_url }
    }

    fn auth_header(&self) -> String {
        format!("Bearer {}", self.token)
    }

    pub fn get(&self, path: &str) -> Result<Value, String> {
        let url = format!("{}{}", self.base_url, path);
        let req = HttpRequest::new(&url)
            .with_method("GET")
            .with_header("Authorization", &self.auth_header())
            .with_header("Content-Type", "application/json");

        let resp = http::request::<()>(&req, None)
            .map_err(|e| format!("GET {path} failed: {e}"))?;

        let status = resp.status_code();
        if status < 200 || status >= 300 {
            let body = String::from_utf8_lossy(&resp.body()).to_string();
            return Err(format!("GET {path} returned HTTP {status}: {body}"));
        }

        serde_json::from_slice(&resp.body())
            .map_err(|e| format!("GET {path} response parse error: {e}"))
    }

    pub fn post(&self, path: &str, body: &Value) -> Result<Value, String> {
        let url = format!("{}{}", self.base_url, path);
        let body_bytes = serde_json::to_vec(body)
            .map_err(|e| format!("POST {path} body serialization failed: {e}"))?;

        let req = HttpRequest::new(&url)
            .with_method("POST")
            .with_header("Authorization", &self.auth_header())
            .with_header("Content-Type", "application/json");

        let resp = http::request(&req, Some(body_bytes))
            .map_err(|e| format!("POST {path} failed: {e}"))?;

        let status = resp.status_code();
        if status < 200 || status >= 300 {
            let body_str = String::from_utf8_lossy(&resp.body()).to_string();
            return Err(format!("POST {path} returned HTTP {status}: {body_str}"));
        }

        if resp.body().is_empty() {
            return Ok(Value::Null);
        }

        serde_json::from_slice(&resp.body())
            .map_err(|e| format!("POST {path} response parse error: {e}"))
    }

    pub fn patch(&self, path: &str, body: &Value) -> Result<(), String> {
        let url = format!("{}{}", self.base_url, path);
        let body_bytes = serde_json::to_vec(body)
            .map_err(|e| format!("PATCH {path} body serialization failed: {e}"))?;

        let req = HttpRequest::new(&url)
            .with_method("PATCH")
            .with_header("Authorization", &self.auth_header())
            .with_header("Content-Type", "application/json");

        let resp = http::request(&req, Some(body_bytes))
            .map_err(|e| format!("PATCH {path} failed: {e}"))?;

        let status = resp.status_code();
        if status < 200 || status >= 300 {
            let body_str = String::from_utf8_lossy(&resp.body()).to_string();
            return Err(format!("PATCH {path} returned HTTP {status}: {body_str}"));
        }

        Ok(())
    }

    pub fn delete(&self, path: &str) -> Result<(), String> {
        let url = format!("{}{}", self.base_url, path);
        let req = HttpRequest::new(&url)
            .with_method("DELETE")
            .with_header("Authorization", &self.auth_header());

        let resp = http::request::<()>(&req, None)
            .map_err(|e| format!("DELETE {path} failed: {e}"))?;

        let status = resp.status_code();
        // 204 No Content is the normal success response for DELETE
        if status < 200 || status >= 300 {
            let body_str = String::from_utf8_lossy(&resp.body()).to_string();
            return Err(format!("DELETE {path} returned HTTP {status}: {body_str}"));
        }

        Ok(())
    }
}

/// Percent-encode a string for use in OData $filter query parameters.
pub fn odata_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            b => {
                out.push('%');
                out.push_str(&format!("{b:02X}"));
            }
        }
    }
    out
}
