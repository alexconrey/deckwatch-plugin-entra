// OAuth2 client credentials token acquisition for Microsoft Entra.
//
// Performs a direct HTTP POST to the token endpoint — no SDK dependency.
// All network I/O goes through extism's host HTTP facility.

use extism_pdk::{http, HttpRequest};

/// Percent-encode a string for use in an application/x-www-form-urlencoded body.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
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

/// Acquire a bearer token for the Microsoft Graph API using the client
/// credentials grant. Called once per `apply()` or `provision()` invocation.
pub fn get_access_token(
    tenant_id: &str,
    client_id: &str,
    client_secret: &str,
) -> Result<String, String> {
    let url = format!(
        "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    );

    let body = format!(
        "grant_type=client_credentials&client_id={}&client_secret={}&scope={}",
        percent_encode(client_id),
        percent_encode(client_secret),
        percent_encode("https://graph.microsoft.com/.default"),
    );

    let req = HttpRequest::new(&url)
        .with_method("POST")
        .with_header("Content-Type", "application/x-www-form-urlencoded");

    let resp = http::request(&req, Some(body.into_bytes()))
        .map_err(|e| format!("token request failed: {e}"))?;

    let status = resp.status_code();
    if status != 200 {
        let body_str = String::from_utf8_lossy(&resp.body()).to_string();
        return Err(format!("token endpoint returned HTTP {status}: {body_str}"));
    }

    let parsed: serde_json::Value = serde_json::from_slice(&resp.body())
        .map_err(|e| format!("failed to parse token response: {e}"))?;

    parsed["access_token"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| "token response missing access_token field".to_string())
}
