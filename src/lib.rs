//! Deckwatch plugin — provisions Microsoft Entra enterprise applications and
//! maps SSO credential values to Kubernetes Ingress annotations.
//!
//! ## WASM entry points
//!
//! - [`metadata`] — static plugin metadata; called once at load time.
//! - [`apply`]    — reads provisioned state, patches the target Ingress; called per deployment event.
//! - [`provision`] — creates the Entra app registration + service principal + SSO config.
//! - [`deprovision`] — deletes the Entra app registration and service principal.
//!
//! ## Per-application configuration
//!
//! All per-application settings (SSO mode, ingress target, annotation mappings)
//! are collected via the provisioning form and stored in the `state` map.
//! `apply()` reads them from `ctx.provisioned_resources["entra/entra_app"]` —
//! no annotations need to be set on the deployment by the operator.
//!
//! ## Host-side testing
//!
//! [`apply_inner`] is a pure function (no Graph API calls) exercised by unit
//! tests. It covers the full provisioned-state → Ingress patch path.

#[cfg(target_arch = "wasm32")]
mod applications;
#[cfg(target_arch = "wasm32")]
mod auth;
#[cfg(target_arch = "wasm32")]
mod graph;
#[cfg(target_arch = "wasm32")]
mod service_principals;

use std::collections::HashMap;

use deckwatch_plugin_sdk::{
    ConfigField, ConfigFieldType, EnvVarSpec, PluginContext, PluginResource, PluginResult,
};
#[cfg(target_arch = "wasm32")]
use deckwatch_plugin_sdk::{
    PluginMetadata, ProvisioningStatus, ResourceDeprovisionRequest, ResourceDeprovisionResult,
    ResourceProvisionRequest, ResourceProvisionResult,
};
#[cfg(target_arch = "wasm32")]
use extism_pdk::*;
use serde_json::{json, Value};

// ── Entra credential resolution ───────────────────────────────────────────────

pub struct EntraCredentials {
    pub tenant_id: String,
    pub client_id: String,
    pub client_secret: String,
}

#[cfg(target_arch = "wasm32")]
impl EntraCredentials {
    pub fn from_config() -> Result<Self, String> {
        let tenant_id = config::get("AZURE_TENANT_ID")
            .map_err(|e| format!("AZURE_TENANT_ID config error: {e}"))?
            .ok_or("AZURE_TENANT_ID not set in plugin config")?;
        let client_id = config::get("AZURE_CLIENT_ID")
            .map_err(|e| format!("AZURE_CLIENT_ID config error: {e}"))?
            .ok_or("AZURE_CLIENT_ID not set in plugin config")?;
        let client_secret = config::get("AZURE_CLIENT_SECRET")
            .map_err(|e| format!("AZURE_CLIENT_SECRET config error: {e}"))?
            .ok_or("AZURE_CLIENT_SECRET not set in plugin config")?;
        Ok(Self { tenant_id, client_id, client_secret })
    }
}

// ── Pure helpers (testable on host) ──────────────────────────────────────────

/// Key names stored in provisioned state (both Graph API outputs and per-app config).
const STATE_CLIENT_ID: &str = "CLIENT_ID";
const STATE_TENANT_ID: &str = "TENANT_ID";
const STATE_SP_OBJECT_ID: &str = "SP_OBJECT_ID";
const STATE_APP_OBJECT_ID: &str = "APP_OBJECT_ID";
const STATE_SSO_MODE: &str = "SSO_MODE";
const STATE_SAML_METADATA_URL: &str = "SAML_METADATA_URL";
const STATE_SAML_LOGIN_URL: &str = "SAML_LOGIN_URL";
const STATE_OIDC_DISCOVERY_URL: &str = "OIDC_DISCOVERY_URL";
const STATE_OIDC_TOKEN_ENDPOINT: &str = "OIDC_TOKEN_ENDPOINT";
const STATE_OIDC_AUTHORIZATION_URL: &str = "OIDC_AUTHORIZATION_URL";
const STATE_TOKEN_SIGNING_CERT_THUMBPRINT: &str = "TOKEN_SIGNING_CERT_THUMBPRINT";
const STATE_ALB_OIDC_JSON: &str = "ALB_OIDC_JSON";
const STATE_INGRESS_NAME: &str = "ENTRA_INGRESS_NAME";
const STATE_INGRESS_NAMESPACE: &str = "ENTRA_INGRESS_NAMESPACE";
const STATE_MAP_CLIENT_ID: &str = "ENTRA_MAP_CLIENT_ID";
const STATE_MAP_TENANT_ID: &str = "ENTRA_MAP_TENANT_ID";
const STATE_MAP_OIDC_JSON: &str = "ENTRA_MAP_OIDC_JSON";
const STATE_MAP_SAML_METADATA_URL: &str = "ENTRA_MAP_SAML_METADATA_URL";
const STATE_MAP_SAML_LOGIN_URL: &str = "ENTRA_MAP_SAML_LOGIN_URL";
const STATE_MAP_CERT_THUMBPRINT: &str = "ENTRA_MAP_CERT_THUMBPRINT";

/// Derive all fixed Entra SSO URLs from the tenant ID and client ID.
pub fn derive_sso_urls(tenant_id: &str) -> (String, String, String, String, String) {
    let saml_metadata_url = format!(
        "https://login.microsoftonline.com/{tenant_id}/federationmetadata/2007-06/federationmetadata.xml"
    );
    let saml_login_url = format!("https://login.microsoftonline.com/{tenant_id}/saml2");
    let oidc_discovery_url = format!(
        "https://login.microsoftonline.com/{tenant_id}/v2.0/.well-known/openid-configuration"
    );
    let oidc_token_endpoint = format!(
        "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    );
    let oidc_authorization_url = format!(
        "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize"
    );
    (
        saml_metadata_url,
        saml_login_url,
        oidc_discovery_url,
        oidc_token_endpoint,
        oidc_authorization_url,
    )
}

/// Build the JSON blob expected by `alb.ingress.kubernetes.io/auth-idp-oidc`.
pub fn build_alb_oidc_json(tenant_id: &str, secret_name: &str) -> String {
    let obj = json!({
        "issuer": format!("https://login.microsoftonline.com/{tenant_id}/v2.0"),
        "authorizationEndpoint": format!("https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize"),
        "tokenEndpoint": format!("https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"),
        "userInfoEndpoint": "https://graph.microsoft.com/oidc/userinfo",
        "secretName": secret_name
    });
    obj.to_string()
}

/// Kubernetes Secret holding the per-app Entra client credentials.
/// Uses `stringData` so values don't need base64 encoding here.
pub fn credentials_secret(
    name: &str,
    namespace: &str,
    client_id: &str,
    client_secret: &str,
) -> Value {
    json!({
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": {
                "managed-by": "deckwatch",
                "plugin": "deckwatch-plugin-entra"
            }
        },
        "stringData": {
            "clientId": client_id,
            "clientSecret": client_secret
        }
    })
}

/// Build an Ingress SSA patch that merges the given annotations.
/// The patch touches only `metadata.annotations` — all other Ingress fields
/// remain under their existing field managers.
pub fn ingress_patch(name: &str, namespace: &str, annotations: HashMap<String, String>) -> Value {
    let ann_map: serde_json::Map<String, Value> = annotations
        .into_iter()
        .map(|(k, v)| (k, Value::String(v)))
        .collect();

    json!({
        "apiVersion": "networking.k8s.io/v1",
        "kind": "Ingress",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "annotations": ann_map
        }
    })
}

/// The name of the credentials Secret for a given deployment.
pub fn secret_name(deployment_name: &str) -> String {
    format!("{deployment_name}-entra-credentials")
}

/// Build a [`PluginResult`] from provisioned state, without any Graph API calls.
///
/// This is the full path for `apply()` — since all required values are already
/// in `ctx.provisioned_resources`, no network calls are needed at reconcile time.
pub fn apply_inner(ctx: &PluginContext) -> PluginResult {
    let Some(state) = ctx.provisioned_resources.get("entra/entra_app") else {
        // Not yet provisioned — nothing to do.
        return PluginResult::default();
    };

    let mut result = PluginResult::default();

    // ── Expose outputs for downstream plugins ─────────────────────────────────
    for key in &[
        STATE_CLIENT_ID,
        STATE_TENANT_ID,
        STATE_SP_OBJECT_ID,
        STATE_APP_OBJECT_ID,
        STATE_SSO_MODE,
        STATE_SAML_METADATA_URL,
        STATE_SAML_LOGIN_URL,
        STATE_OIDC_DISCOVERY_URL,
        STATE_OIDC_TOKEN_ENDPOINT,
        STATE_OIDC_AUTHORIZATION_URL,
        STATE_TOKEN_SIGNING_CERT_THUMBPRINT,
    ] {
        if let Some(v) = state.get(*key).filter(|s| !s.is_empty()) {
            result.outputs.insert(key.to_lowercase(), v.clone());
        }
    }

    // ── Inject Secret references into the workload ────────────────────────────
    // Allows the application itself to use the Entra credentials (e.g. for
    // on-behalf-of flows) without duplicating the values in env vars.
    let sec = secret_name(&ctx.deployment_name);
    result
        .env_vars
        .push(EnvVarSpec::secret_key_ref("ENTRA_CLIENT_ID", &sec, "clientId"));
    result
        .env_vars
        .push(EnvVarSpec::secret_key_ref("ENTRA_CLIENT_SECRET", &sec, "clientSecret"));
    if let Some(tid) = state.get(STATE_TENANT_ID).filter(|s| !s.is_empty()) {
        result
            .env_vars
            .push(EnvVarSpec::value("ENTRA_TENANT_ID", tid));
    }

    // ── Build Ingress annotation patch ────────────────────────────────────────
    let ingress_name = state
        .get(STATE_INGRESS_NAME)
        .filter(|s| !s.is_empty())
        .cloned()
        .unwrap_or_else(|| ctx.deployment_name.clone());
    let ingress_ns = state
        .get(STATE_INGRESS_NAMESPACE)
        .filter(|s| !s.is_empty())
        .cloned()
        .unwrap_or_else(|| ctx.namespace.clone());

    // Each ENTRA_MAP_* key holds a target annotation name.
    // When set, resolve the corresponding value from state and include it in the patch.
    let mappings: &[(&str, &str)] = &[
        (STATE_MAP_CLIENT_ID, STATE_CLIENT_ID),
        (STATE_MAP_TENANT_ID, STATE_TENANT_ID),
        (STATE_MAP_OIDC_JSON, STATE_ALB_OIDC_JSON),
        (STATE_MAP_SAML_METADATA_URL, STATE_SAML_METADATA_URL),
        (STATE_MAP_SAML_LOGIN_URL, STATE_SAML_LOGIN_URL),
        (STATE_MAP_CERT_THUMBPRINT, STATE_TOKEN_SIGNING_CERT_THUMBPRINT),
    ];

    let mut ann: HashMap<String, String> = HashMap::new();
    for (map_key, value_key) in mappings {
        if let Some(target_annotation) = state.get(*map_key).filter(|s| !s.is_empty()) {
            if let Some(value) = state.get(*value_key).filter(|s| !s.is_empty()) {
                ann.insert(target_annotation.clone(), value.clone());
            }
        }
    }

    if !ann.is_empty() {
        result
            .kubernetes_resources
            .push(ingress_patch(&ingress_name, &ingress_ns, ann));
    }

    result
}

// ── Resource declaration (pure — testable on host) ────────────────────────────

pub fn entra_app_resource() -> PluginResource {
    PluginResource {
        id: "entra_app".into(),
        label: "Entra Enterprise Application".into(),
        icon: "mdi-microsoft-azure".into(),
        description: "Create a Microsoft Entra enterprise application and map its SSO credentials to Ingress annotations.".into(),
        singleton: true,
        fields: vec![
            ConfigField {
                key: "app_display_name".into(),
                label: "Application Display Name".into(),
                description: "Display name for the app registration in the Entra portal.".into(),
                field_type: ConfigFieldType::String,
                default: None,
                required: true,
                options: vec![],
                env_source: None,
            },
            ConfigField {
                key: "sso_mode".into(),
                label: "SSO Mode".into(),
                description: "OIDC for modern apps (ALB OIDC auth, OAuth2). SAML for legacy apps.".into(),
                field_type: ConfigFieldType::Select,
                default: Some("oidc".into()),
                required: true,
                options: vec!["oidc".into(), "saml".into()],
                env_source: None,
            },
            ConfigField {
                key: "reply_url".into(),
                label: "Reply URL".into(),
                description: "OIDC redirect URI or SAML ACS URL. e.g. https://my-app.example.com/oauth2/idpresponse".into(),
                field_type: ConfigFieldType::String,
                default: None,
                required: true,
                options: vec![],
                env_source: None,
            },
            ConfigField {
                key: "ingress_name".into(),
                label: "Ingress Name".into(),
                description: "Name of the Kubernetes Ingress to annotate. Defaults to the deployment name.".into(),
                field_type: ConfigFieldType::String,
                default: None,
                required: false,
                options: vec![],
                env_source: None,
            },
            ConfigField {
                key: "ingress_namespace".into(),
                label: "Ingress Namespace".into(),
                description: "Namespace of the Ingress. Defaults to the application namespace.".into(),
                field_type: ConfigFieldType::String,
                default: None,
                required: false,
                options: vec![],
                env_source: None,
            },
            ConfigField {
                key: "map_client_id".into(),
                label: "Map: Client ID → Annotation".into(),
                description: "Ingress annotation key that should receive the Entra client ID (appId). e.g. alb.ingress.kubernetes.io/auth-idp-oidc-client-id".into(),
                field_type: ConfigFieldType::String,
                default: None,
                required: false,
                options: vec![],
                env_source: None,
            },
            ConfigField {
                key: "map_tenant_id".into(),
                label: "Map: Tenant ID → Annotation".into(),
                description: "Ingress annotation key that should receive the Entra tenant ID.".into(),
                field_type: ConfigFieldType::String,
                default: None,
                required: false,
                options: vec![],
                env_source: None,
            },
            ConfigField {
                key: "map_oidc_json".into(),
                label: "Map: ALB OIDC JSON → Annotation".into(),
                description: "Ingress annotation key for the synthesized ALB OIDC JSON blob. e.g. alb.ingress.kubernetes.io/auth-idp-oidc".into(),
                field_type: ConfigFieldType::String,
                default: None,
                required: false,
                options: vec![],
                env_source: None,
            },
            ConfigField {
                key: "map_saml_metadata_url".into(),
                label: "Map: SAML Metadata URL → Annotation".into(),
                description: "Ingress annotation key for the SAML federation metadata URL.".into(),
                field_type: ConfigFieldType::String,
                default: None,
                required: false,
                options: vec![],
                env_source: None,
            },
            ConfigField {
                key: "map_saml_login_url".into(),
                label: "Map: SAML Login URL → Annotation".into(),
                description: "Ingress annotation key for the SAML single sign-on URL.".into(),
                field_type: ConfigFieldType::String,
                default: None,
                required: false,
                options: vec![],
                env_source: None,
            },
            ConfigField {
                key: "map_cert_thumbprint".into(),
                label: "Map: Token Signing Cert Thumbprint → Annotation".into(),
                description: "Ingress annotation key for the SAML token-signing certificate thumbprint (SAML mode only).".into(),
                field_type: ConfigFieldType::String,
                default: None,
                required: false,
                options: vec![],
                env_source: None,
            },
        ],
        output_keys: vec![
            STATE_CLIENT_ID.into(),
            STATE_TENANT_ID.into(),
            STATE_SP_OBJECT_ID.into(),
            STATE_APP_OBJECT_ID.into(),
            STATE_SSO_MODE.into(),
            STATE_SAML_METADATA_URL.into(),
            STATE_SAML_LOGIN_URL.into(),
            STATE_OIDC_DISCOVERY_URL.into(),
            STATE_OIDC_TOKEN_ENDPOINT.into(),
            STATE_OIDC_AUTHORIZATION_URL.into(),
            STATE_TOKEN_SIGNING_CERT_THUMBPRINT.into(),
            STATE_ALB_OIDC_JSON.into(),
        ],
    }
}

// ── WASM entry points ─────────────────────────────────────────────────────────

#[cfg(target_arch = "wasm32")]
#[plugin_fn]
pub fn metadata() -> FnResult<Json<PluginMetadata>> {
    Ok(Json(PluginMetadata {
        name: "entra".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        description: "Provisions Microsoft Entra enterprise applications and maps SSO values to Kubernetes Ingress annotations".into(),
        provides: vec!["entra:enterprise-application".into()],
        depends_on: vec![],
        optional_depends_on: vec![],
        config_schema: vec![
            ConfigField {
                key: "AZURE_TENANT_ID".into(),
                label: "Azure Tenant ID".into(),
                description: "The Entra tenant where applications will be created.".into(),
                field_type: ConfigFieldType::String,
                default: None,
                required: true,
                options: vec![],
                env_source: Some("AZURE_TENANT_ID".into()),
            },
            ConfigField {
                key: "AZURE_CLIENT_ID".into(),
                label: "Deckwatch Bot Client ID".into(),
                description: "Client ID of the Entra app registration used by deckwatch to manage applications. Requires Application.ReadWrite.All.".into(),
                field_type: ConfigFieldType::String,
                default: None,
                required: true,
                options: vec![],
                env_source: Some("AZURE_CLIENT_ID".into()),
            },
            ConfigField {
                key: "AZURE_CLIENT_SECRET".into(),
                label: "Deckwatch Bot Client Secret".into(),
                description: "Client secret for the deckwatch bot app registration.".into(),
                field_type: ConfigFieldType::Secret,
                default: None,
                required: true,
                options: vec![],
                env_source: Some("AZURE_CLIENT_SECRET".into()),
            },
        ],
        resources: vec![entra_app_resource()],
    }))
}

#[cfg(target_arch = "wasm32")]
#[plugin_fn]
pub fn apply(Json(ctx): Json<PluginContext>) -> FnResult<Json<PluginResult>> {
    Ok(Json(apply_inner(&ctx)))
}

#[cfg(target_arch = "wasm32")]
#[plugin_fn]
pub fn provision(
    Json(req): Json<ResourceProvisionRequest>,
) -> FnResult<Json<ResourceProvisionResult>> {
    use applications::{add_password, ensure_application};
    use auth::get_access_token;
    use graph::GraphClient;
    use service_principals::{
        add_token_signing_certificate, configure_sso, ensure_service_principal,
    };

    let mut result = ResourceProvisionResult::default();

    if req.resource_id != "entra_app" {
        result.errors.push(format!("unknown resource_id: {}", req.resource_id));
        result.status = ProvisioningStatus::Failed;
        return Ok(Json(result));
    }

    // ── Resolve bot credentials ───────────────────────────────────────────────
    let creds = match EntraCredentials::from_config() {
        Ok(c) => c,
        Err(e) => {
            result.errors.push(format!("credential error: {e}"));
            result.status = ProvisioningStatus::Failed;
            return Ok(Json(result));
        }
    };

    // ── Extract per-app form fields ───────────────────────────────────────────
    let f = |key: &str| req.fields.get(key).cloned().unwrap_or_default();
    let app_display_name = f("app_display_name");
    let sso_mode = {
        let v = f("sso_mode");
        if v.is_empty() { "oidc".to_string() } else { v }
    };
    let reply_url = f("reply_url");
    let ingress_name = f("ingress_name");
    let ingress_namespace = f("ingress_namespace");

    if app_display_name.is_empty() {
        result.errors.push("app_display_name is required".into());
        result.status = ProvisioningStatus::Failed;
        return Ok(Json(result));
    }

    // ── Acquire Graph API token ───────────────────────────────────────────────
    let token = match get_access_token(&creds.tenant_id, &creds.client_id, &creds.client_secret) {
        Ok(t) => t,
        Err(e) => {
            result.errors.push(format!("token acquisition failed: {e}"));
            result.status = ProvisioningStatus::Failed;
            return Ok(Json(result));
        }
    };
    let client = GraphClient::new(token);

    // ── 1. Ensure app registration ────────────────────────────────────────────
    let app_info = match ensure_application(&app_display_name, &reply_url, &client) {
        Ok(info) => info,
        Err(e) => {
            result.errors.push(format!("ensure_application failed: {e}"));
            result.status = ProvisioningStatus::Failed;
            return Ok(Json(result));
        }
    };

    // ── 2. Add client secret ──────────────────────────────────────────────────
    let client_secret_value = match add_password(&app_info.object_id, &app_display_name, &client) {
        Ok(s) => s,
        Err(e) => {
            result.errors.push(format!("add_password failed: {e}"));
            result.status = ProvisioningStatus::Failed;
            return Ok(Json(result));
        }
    };

    // ── 3. Ensure service principal ───────────────────────────────────────────
    let sp_id = match ensure_service_principal(&app_info.app_id, &client) {
        Ok(id) => id,
        Err(e) => {
            result.errors.push(format!("ensure_service_principal failed: {e}"));
            result.status = ProvisioningStatus::Failed;
            return Ok(Json(result));
        }
    };

    // ── 4. Configure SSO ─────────────────────────────────────────────────────
    if let Err(e) = configure_sso(&sp_id, &sso_mode, &reply_url, &client) {
        result.warnings.push(format!("configure_sso failed (non-fatal): {e}"));
    }

    // ── 5. Add SAML signing certificate (SAML only) ───────────────────────────
    let cert_thumbprint = if sso_mode == "saml" {
        match add_token_signing_certificate(&sp_id, &app_display_name, &client) {
            Ok(thumb) => thumb,
            Err(e) => {
                result.warnings.push(format!("add_token_signing_certificate failed: {e}"));
                String::new()
            }
        }
    } else {
        String::new()
    };

    // ── 6. Derive fixed SSO URLs ──────────────────────────────────────────────
    let (saml_metadata_url, saml_login_url, oidc_discovery_url, oidc_token_endpoint, oidc_authorization_url) =
        derive_sso_urls(&creds.tenant_id);

    // ── 7. Build credentials Secret name ─────────────────────────────────────
    let sec_name = secret_name(&req.application_name);

    // ── 8. Build ALB OIDC JSON ────────────────────────────────────────────────
    let alb_oidc_json = build_alb_oidc_json(&creds.tenant_id, &sec_name);

    // ── 9. Persist state ──────────────────────────────────────────────────────
    // Graph API outputs
    result.state.insert(STATE_CLIENT_ID.into(), app_info.app_id.clone());
    result.state.insert(STATE_TENANT_ID.into(), creds.tenant_id.clone());
    result.state.insert(STATE_SP_OBJECT_ID.into(), sp_id.clone());
    result.state.insert(STATE_APP_OBJECT_ID.into(), app_info.object_id.clone());
    result.state.insert(STATE_SSO_MODE.into(), sso_mode.clone());
    result.state.insert(STATE_SAML_METADATA_URL.into(), saml_metadata_url);
    result.state.insert(STATE_SAML_LOGIN_URL.into(), saml_login_url);
    result.state.insert(STATE_OIDC_DISCOVERY_URL.into(), oidc_discovery_url);
    result.state.insert(STATE_OIDC_TOKEN_ENDPOINT.into(), oidc_token_endpoint);
    result.state.insert(STATE_OIDC_AUTHORIZATION_URL.into(), oidc_authorization_url);
    result.state.insert(STATE_ALB_OIDC_JSON.into(), alb_oidc_json);
    if !cert_thumbprint.is_empty() {
        result.state.insert(STATE_TOKEN_SIGNING_CERT_THUMBPRINT.into(), cert_thumbprint);
    }

    // Per-app config — stored so apply() can read them without annotations
    result.state.insert(STATE_INGRESS_NAME.into(), ingress_name);
    result.state.insert(STATE_INGRESS_NAMESPACE.into(), ingress_namespace);
    result.state.insert(STATE_MAP_CLIENT_ID.into(), f("map_client_id"));
    result.state.insert(STATE_MAP_TENANT_ID.into(), f("map_tenant_id"));
    result.state.insert(STATE_MAP_OIDC_JSON.into(), f("map_oidc_json"));
    result.state.insert(STATE_MAP_SAML_METADATA_URL.into(), f("map_saml_metadata_url"));
    result.state.insert(STATE_MAP_SAML_LOGIN_URL.into(), f("map_saml_login_url"));
    result.state.insert(STATE_MAP_CERT_THUMBPRINT.into(), f("map_cert_thumbprint"));

    // ── 10. Kubernetes resources ──────────────────────────────────────────────
    let k8s_ns = if req.namespace.is_empty() {
        "default".to_string()
    } else {
        req.namespace.clone()
    };

    result.kubernetes_resources.push(credentials_secret(
        &sec_name,
        &k8s_ns,
        &app_info.app_id,
        &client_secret_value,
    ));

    result.status = ProvisioningStatus::Available;
    Ok(Json(result))
}

#[cfg(target_arch = "wasm32")]
#[plugin_fn]
pub fn deprovision(
    Json(req): Json<ResourceDeprovisionRequest>,
) -> FnResult<Json<ResourceDeprovisionResult>> {
    use auth::get_access_token;
    use graph::GraphClient;
    use service_principals::delete_service_principal;
    use applications::delete_application;

    let mut result = ResourceDeprovisionResult::default();

    let creds = match EntraCredentials::from_config() {
        Ok(c) => c,
        Err(e) => {
            result.errors.push(format!("credential error: {e}"));
            result.message = "Deprovisioning skipped — credentials unavailable.".into();
            return Ok(Json(result));
        }
    };

    let token = match get_access_token(&creds.tenant_id, &creds.client_id, &creds.client_secret) {
        Ok(t) => t,
        Err(e) => {
            result.errors.push(format!("token acquisition failed: {e}"));
            result.message = "Deprovisioning skipped — could not acquire Graph API token.".into();
            return Ok(Json(result));
        }
    };
    let client = GraphClient::new(token);

    let sp_id = req.state.get(STATE_SP_OBJECT_ID).cloned().unwrap_or_default();
    let app_object_id = req.state.get(STATE_APP_OBJECT_ID).cloned().unwrap_or_default();
    let client_id = req.state.get(STATE_CLIENT_ID).cloned().unwrap_or_default();

    // Delete service principal first (app registration cannot be deleted while SP exists).
    if !sp_id.is_empty() {
        if let Err(e) = delete_service_principal(&sp_id, &client) {
            result.errors.push(format!("delete_service_principal failed: {e}"));
        }
    }

    if !app_object_id.is_empty() {
        if let Err(e) = delete_application(&app_object_id, &client) {
            result.errors.push(format!("delete_application failed: {e}"));
        }
    }

    if result.errors.is_empty() {
        result.message = format!(
            "Deleted Entra app registration (clientId: {client_id}) and its service principal. \
             The Kubernetes credentials Secret must be removed manually if needed."
        );
    } else {
        result.message = format!(
            "Deprovisioning completed with errors for clientId {client_id} — manual cleanup may be required."
        );
    }

    Ok(Json(result))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_state(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    fn ctx_no_state() -> PluginContext {
        PluginContext {
            namespace: "production".into(),
            deployment_name: "my-app".into(),
            annotations: HashMap::new(),
            labels: HashMap::new(),
            plugin_outputs: HashMap::new(),
            provisioned_resources: HashMap::new(),
        }
    }

    fn ctx_with_state(state: HashMap<String, String>) -> PluginContext {
        let mut provisioned = HashMap::new();
        provisioned.insert("entra/entra_app".into(), state);
        PluginContext {
            namespace: "production".into(),
            deployment_name: "my-app".into(),
            annotations: HashMap::new(),
            labels: HashMap::new(),
            plugin_outputs: HashMap::new(),
            provisioned_resources: provisioned,
        }
    }

    fn find_env<'a>(result: &'a PluginResult, name: &str) -> Option<&'a str> {
        result.env_vars.iter().find(|e| e.name == name).map(|e| e.value.as_str())
    }

    // 1. No provisioned state → empty result.
    #[test]
    fn no_state_returns_default() {
        let result = apply_inner(&ctx_no_state());
        assert!(result.env_vars.is_empty());
        assert!(result.kubernetes_resources.is_empty());
        assert!(result.outputs.is_empty());
    }

    // 2. Provisioned state present → Secret refs and outputs populated.
    #[test]
    fn provisioned_state_injects_secret_refs_and_outputs() {
        let state = make_state(&[
            (STATE_CLIENT_ID, "test-client-id"),
            (STATE_TENANT_ID, "test-tenant-id"),
            (STATE_SP_OBJECT_ID, "sp-123"),
            (STATE_APP_OBJECT_ID, "app-456"),
            (STATE_SSO_MODE, "oidc"),
        ]);
        let result = apply_inner(&ctx_with_state(state));

        // Secret refs injected
        let client_id_var = result.env_vars.iter().find(|e| e.name == "ENTRA_CLIENT_ID");
        assert!(client_id_var.is_some(), "ENTRA_CLIENT_ID secret ref expected");
        let skr = client_id_var.unwrap().value_from.as_ref().unwrap().secret_key_ref.as_ref().unwrap();
        assert_eq!(skr.name, "my-app-entra-credentials");
        assert_eq!(skr.key, "clientId");

        // Static tenant env var
        assert_eq!(find_env(&result, "ENTRA_TENANT_ID"), Some("test-tenant-id"));

        // Outputs map populated
        assert_eq!(result.outputs.get("client_id").map(String::as_str), Some("test-client-id"));
        assert_eq!(result.outputs.get("tenant_id").map(String::as_str), Some("test-tenant-id"));
        assert_eq!(result.outputs.get("sp_object_id").map(String::as_str), Some("sp-123"));
    }

    // 3. Annotation mapping → Ingress patch emitted.
    #[test]
    fn annotation_mapping_produces_ingress_patch() {
        let state = make_state(&[
            (STATE_CLIENT_ID, "test-client-id"),
            (STATE_TENANT_ID, "test-tenant-id"),
            (STATE_MAP_CLIENT_ID, "alb.ingress.kubernetes.io/auth-idp-oidc-client-id"),
            (STATE_MAP_TENANT_ID, "myorg.io/entra-tenant-id"),
            (STATE_INGRESS_NAME, "my-ingress"),
            (STATE_INGRESS_NAMESPACE, "production"),
        ]);
        let result = apply_inner(&ctx_with_state(state));

        assert_eq!(result.kubernetes_resources.len(), 1);
        let patch = &result.kubernetes_resources[0];
        assert_eq!(patch["kind"], "Ingress");
        assert_eq!(patch["metadata"]["name"], "my-ingress");
        assert_eq!(patch["metadata"]["namespace"], "production");
        assert_eq!(
            patch["metadata"]["annotations"]["alb.ingress.kubernetes.io/auth-idp-oidc-client-id"],
            "test-client-id"
        );
        assert_eq!(
            patch["metadata"]["annotations"]["myorg.io/entra-tenant-id"],
            "test-tenant-id"
        );
    }

    // 4. Ingress defaults to deployment name and deployment namespace when not set.
    #[test]
    fn ingress_defaults_to_deployment_name_and_namespace() {
        let state = make_state(&[
            (STATE_CLIENT_ID, "cid"),
            (STATE_MAP_CLIENT_ID, "some-annotation"),
            // ENTRA_INGRESS_NAME and ENTRA_INGRESS_NAMESPACE intentionally absent
        ]);
        let ctx = ctx_with_state(state);
        let result = apply_inner(&ctx);

        let patch = &result.kubernetes_resources[0];
        assert_eq!(patch["metadata"]["name"], "my-app");
        assert_eq!(patch["metadata"]["namespace"], "production");
    }

    // 5. No mappings set → no Ingress patch emitted.
    #[test]
    fn no_mappings_no_ingress_patch() {
        let state = make_state(&[
            (STATE_CLIENT_ID, "cid"),
            (STATE_TENANT_ID, "tid"),
            // No ENTRA_MAP_* keys set
        ]);
        let result = apply_inner(&ctx_with_state(state));
        assert!(
            result.kubernetes_resources.is_empty(),
            "no Ingress patch expected when no mappings are configured"
        );
    }

    // 6. ALB OIDC JSON mapping uses pre-computed value from state.
    #[test]
    fn alb_oidc_json_mapping_uses_state_value() {
        let alb_json = r#"{"issuer":"https://login.microsoftonline.com/tid/v2.0"}"#;
        let state = make_state(&[
            (STATE_ALB_OIDC_JSON, alb_json),
            (STATE_MAP_OIDC_JSON, "alb.ingress.kubernetes.io/auth-idp-oidc"),
        ]);
        let result = apply_inner(&ctx_with_state(state));

        assert_eq!(result.kubernetes_resources.len(), 1);
        assert_eq!(
            result.kubernetes_resources[0]["metadata"]["annotations"]
                ["alb.ingress.kubernetes.io/auth-idp-oidc"],
            alb_json
        );
    }

    // 7. Mapping key present but value absent → annotation not included in patch.
    #[test]
    fn mapping_with_missing_value_omitted_from_patch() {
        let state = make_state(&[
            (STATE_CLIENT_ID, "cid"),
            (STATE_MAP_CLIENT_ID, "alb.ingress.kubernetes.io/auth-idp-oidc-client-id"),
            (STATE_MAP_CERT_THUMBPRINT, "some-annotation"),
            // TOKEN_SIGNING_CERT_THUMBPRINT absent — SAML cert not generated for OIDC app
        ]);
        let result = apply_inner(&ctx_with_state(state));

        let patch = &result.kubernetes_resources[0];
        let ann = &patch["metadata"]["annotations"];
        assert!(ann["alb.ingress.kubernetes.io/auth-idp-oidc-client-id"].is_string());
        assert!(ann["some-annotation"].is_null(), "absent value must not produce annotation");
    }

    // 8. derive_sso_urls returns correct Entra URL shapes.
    #[test]
    fn derive_sso_urls_correct_shape() {
        let (saml_meta, saml_login, oidc_disc, oidc_tok, oidc_auth) =
            derive_sso_urls("my-tenant-id");
        assert!(saml_meta.contains("my-tenant-id"));
        assert!(saml_meta.contains("federationmetadata"));
        assert!(saml_login.contains("saml2"));
        assert!(oidc_disc.contains("openid-configuration"));
        assert!(oidc_tok.contains("oauth2/v2.0/token"));
        assert!(oidc_auth.contains("oauth2/v2.0/authorize"));
    }

    // 9. build_alb_oidc_json embeds tenant ID and secret name.
    #[test]
    fn build_alb_oidc_json_contains_expected_fields() {
        let json_str = build_alb_oidc_json("my-tenant", "my-app-entra-credentials");
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert!(v["issuer"].as_str().unwrap().contains("my-tenant"));
        assert_eq!(v["secretName"], "my-app-entra-credentials");
        assert!(v["tokenEndpoint"].is_string());
        assert!(v["authorizationEndpoint"].is_string());
        assert!(v["userInfoEndpoint"].is_string());
    }

    // 10. entra_app_resource() has required fields and output_keys.
    #[test]
    fn entra_app_resource_structure() {
        let r = entra_app_resource();
        assert_eq!(r.id, "entra_app");
        assert!(r.singleton, "must be singleton — one Entra app per deckwatch application");
        assert!(r.fields.iter().any(|f| f.key == "app_display_name" && f.required));
        assert!(r.fields.iter().any(|f| f.key == "sso_mode"));
        assert!(r.fields.iter().any(|f| f.key == "reply_url" && f.required));
        assert!(r.fields.iter().any(|f| f.key == "map_client_id"));
        assert!(r.fields.iter().any(|f| f.key == "map_oidc_json"));
        assert!(r.output_keys.iter().any(|k| k == STATE_CLIENT_ID));
        assert!(r.output_keys.iter().any(|k| k == STATE_ALB_OIDC_JSON));
    }

    // 11. secret_name convention.
    #[test]
    fn secret_name_convention() {
        assert_eq!(secret_name("my-app"), "my-app-entra-credentials");
    }

    // 12. ingress_patch produces valid SSA-ready JSON.
    #[test]
    fn ingress_patch_structure() {
        let mut ann = HashMap::new();
        ann.insert("foo/bar".into(), "baz".into());
        let patch = ingress_patch("my-ing", "my-ns", ann);
        assert_eq!(patch["apiVersion"], "networking.k8s.io/v1");
        assert_eq!(patch["kind"], "Ingress");
        assert_eq!(patch["metadata"]["name"], "my-ing");
        assert_eq!(patch["metadata"]["namespace"], "my-ns");
        assert_eq!(patch["metadata"]["annotations"]["foo/bar"], "baz");
    }
}
