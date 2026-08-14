// Microsoft Graph /applications endpoint operations.
//
// Implements idempotent ensure_application: looks up by displayName first,
// creates only if not found. Callers always get back the same AppInfo
// regardless of whether this is the first or nth provisioning call.

use crate::graph::{odata_encode, GraphClient};
use serde_json::json;

pub struct AppInfo {
    /// The application's client ID (appId). Used everywhere Entra needs "the app".
    pub app_id: String,
    /// The object ID used for Graph API management operations (not the client ID).
    pub object_id: String,
}

/// Find an existing application by display name. Returns None if not found.
fn find_by_display_name(
    display_name: &str,
    client: &GraphClient,
) -> Result<Option<AppInfo>, String> {
    let filter = format!(
        "displayName eq '{}'",
        display_name.replace('\'', "\\'")
    );
    let path = format!(
        "/applications?$filter={}&$select=id,appId,displayName",
        odata_encode(&filter)
    );

    let resp = client.get(&path)?;

    let values = resp["value"]
        .as_array()
        .ok_or_else(|| "unexpected response shape from /applications".to_string())?;

    if values.is_empty() {
        return Ok(None);
    }

    let app = &values[0];
    let app_id = app["appId"]
        .as_str()
        .ok_or("missing appId in application response")?
        .to_string();
    let object_id = app["id"]
        .as_str()
        .ok_or("missing id in application response")?
        .to_string();

    Ok(Some(AppInfo { app_id, object_id }))
}

/// Ensure an application registration exists. Creates it if not found.
///
/// For OIDC: `reply_url` is the redirect URI.
/// For SAML: `reply_url` is the ACS (Assertion Consumer Service) URL; it is
/// stored on the service principal's SAML config, not the app registration,
/// but we record it here for idempotency on the web.redirectUris too.
pub fn ensure_application(
    display_name: &str,
    reply_url: &str,
    client: &GraphClient,
) -> Result<AppInfo, String> {
    if let Some(existing) = find_by_display_name(display_name, client)? {
        return Ok(existing);
    }

    let body = json!({
        "displayName": display_name,
        "signInAudience": "AzureADMyOrg",
        "web": {
            "redirectUris": [reply_url]
        }
    });

    let resp = client.post("/applications", &body)?;

    let app_id = resp["appId"]
        .as_str()
        .ok_or("missing appId in create application response")?
        .to_string();
    let object_id = resp["id"]
        .as_str()
        .ok_or("missing id in create application response")?
        .to_string();

    Ok(AppInfo { app_id, object_id })
}

/// Add a client secret to an application. Returns the secret value.
///
/// The secret value is only available in this response — Graph API never
/// returns it again. Callers must persist it immediately.
pub fn add_password(object_id: &str, display_name: &str, client: &GraphClient) -> Result<String, String> {
    let body = json!({
        "passwordCredential": {
            "displayName": format!("{display_name} — managed by deckwatch")
        }
    });

    let resp = client.post(
        &format!("/applications/{object_id}/addPassword"),
        &body,
    )?;

    resp["secretText"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| "missing secretText in addPassword response".to_string())
}

/// Delete an application registration. Idempotent — 404 is treated as success.
pub fn delete_application(object_id: &str, client: &GraphClient) -> Result<(), String> {
    match client.delete(&format!("/applications/{object_id}")) {
        Ok(()) => Ok(()),
        Err(e) if e.contains("HTTP 404") => Ok(()),
        Err(e) => Err(e),
    }
}
