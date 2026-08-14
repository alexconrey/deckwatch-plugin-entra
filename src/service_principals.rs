// Microsoft Graph /servicePrincipals endpoint operations.
//
// A service principal is the per-tenant instantiation of an app registration —
// it is the object that operators see as an "enterprise application" in the
// Entra portal. Entra SSO configuration lives here, not on the app registration.

use crate::graph::{odata_encode, GraphClient};
use serde_json::json;

/// Find an existing service principal by appId. Returns the SP object ID or None.
fn find_by_app_id(app_id: &str, client: &GraphClient) -> Result<Option<String>, String> {
    let filter = format!("appId eq '{app_id}'");
    let path = format!(
        "/servicePrincipals?$filter={}&$select=id,appId",
        odata_encode(&filter)
    );

    let resp = client.get(&path)?;

    let values = resp["value"]
        .as_array()
        .ok_or_else(|| "unexpected response shape from /servicePrincipals".to_string())?;

    if values.is_empty() {
        return Ok(None);
    }

    let sp_id = values[0]["id"]
        .as_str()
        .ok_or("missing id in servicePrincipal response")?
        .to_string();

    Ok(Some(sp_id))
}

/// Ensure a service principal exists for the given app registration. Creates it
/// if not found. Returns the service principal object ID.
pub fn ensure_service_principal(app_id: &str, client: &GraphClient) -> Result<String, String> {
    if let Some(existing_id) = find_by_app_id(app_id, client)? {
        return Ok(existing_id);
    }

    let body = json!({ "appId": app_id });
    let resp = client.post("/servicePrincipals", &body)?;

    resp["id"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| "missing id in create servicePrincipal response".to_string())
}

/// Configure SSO on the service principal.
///
/// For `sso_mode = "saml"`: sets `preferredSingleSignOnMode` and
/// `samlSingleSignOnSettings`. The SAML reply URL is also set here because
/// it belongs to the SP's SAML configuration, not the app registration.
///
/// For `sso_mode = "oidc"`: no special SSO mode configuration needed — the
/// app registration's web.redirectUris already handle OIDC flows.
pub fn configure_sso(
    sp_id: &str,
    sso_mode: &str,
    reply_url: &str,
    client: &GraphClient,
) -> Result<(), String> {
    if sso_mode != "saml" {
        return Ok(());
    }

    let body = json!({
        "preferredSingleSignOnMode": "saml",
        "samlSingleSignOnSettings": {
            "relayState": ""
        },
        "replyUrls": [reply_url]
    });

    client.patch(&format!("/servicePrincipals/{sp_id}"), &body)
}

/// Add a self-signed SAML token-signing certificate to the service principal.
/// Returns the certificate thumbprint. Idempotent only in the sense that
/// calling it again adds a second certificate — callers should check whether
/// a certificate already exists in provisioned state before calling.
pub fn add_token_signing_certificate(
    sp_id: &str,
    display_name: &str,
    client: &GraphClient,
) -> Result<String, String> {
    let body = json!({
        "displayName": format!("CN={display_name}"),
        "endDateTime": "2028-01-01T00:00:00Z"
    });

    let resp = client.post(
        &format!("/servicePrincipals/{sp_id}/addTokenSigningCertificate"),
        &body,
    )?;

    resp["thumbprint"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| "missing thumbprint in addTokenSigningCertificate response".to_string())
}

/// Delete a service principal. Idempotent — 404 is treated as success.
pub fn delete_service_principal(sp_id: &str, client: &GraphClient) -> Result<(), String> {
    match client.delete(&format!("/servicePrincipals/{sp_id}")) {
        Ok(()) => Ok(()),
        Err(e) if e.contains("HTTP 404") => Ok(()),
        Err(e) => Err(e),
    }
}
