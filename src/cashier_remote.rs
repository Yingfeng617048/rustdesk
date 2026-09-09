use hbb_common::{
    config::Config,
    log,
    password_security::{decrypt_str_or_original, encrypt_str_or_original},
    tokio,
};
use serde::{Deserialize, Serialize};
use std::{
    sync::{Mutex, Once},
    time::Duration,
};

const API_BASE_URL_OPTION: &str = "cashier-api-base-url";
const DEVICE_ID_OPTION: &str = "cashier-device-id";
const DEVICE_SECRET_OPTION: &str = "cashier-device-secret";
const DEVICE_UUID_OPTION: &str = "cashier-device-uuid";
const PAIRING_ID_OPTION: &str = "cashier-pairing-id";
const PAIRING_SECRET_OPTION: &str = "cashier-pairing-secret";
const PAIRING_DEVICE_SECRET_OPTION: &str = "cashier-pairing-device-secret";
const REBIND_AUTHORIZATION_OPTION: &str = "cashier-rebind-authorization";
const REBIND_AUTHORIZATION_EXPIRES_AT_OPTION: &str =
    "cashier-rebind-authorization-expires-at";
// 必须与果次方助手和生产 hbbs/hbbr 配置保持一致。命令不接受外部地址参数，
// 防止普通本地用户借同步接口把服务重定向到非授权服务器。
const FIXED_ID_SERVER: &str = "162.14.109.182";
const FIXED_RELAY_SERVER: &str = "162.14.109.182";
const FIXED_PUBLIC_KEY: &str = "L1kuWKlf+T9Sqmnf+yBvxjrUOm9FvQ9iaxm2gVZX2m8=";
const SECRET_ENCRYPTION_VERSION: &str = "00";
const SECRET_MAX_LEN: usize = 128;
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
const SESSION_POLL_INTERVAL: Duration = Duration::from_secs(1);
const SESSION_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Clone)]
struct DeviceCredential {
    id: i32,
    secret: String,
}

#[derive(Clone)]
struct ActiveSession {
    id: i32,
    access_key: String,
    expires_at: i64,
    connected: bool,
}

lazy_static::lazy_static! {
    static ref ACTIVE_SESSION: Mutex<Option<ActiveSession>> = Mutex::new(None);
    static ref CONSUMED_SESSION_ID: Mutex<Option<i32>> = Mutex::new(None);
    static ref ENGINE_INSTANCE_ID: String = uuid::Uuid::new_v4().simple().to_string();
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RegisterRequest {
    enrollment_token: String,
    device_uuid: String,
    rustdesk_id: String,
    name: String,
    hostname: String,
    operating_system: String,
    client_version: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegisterResponse {
    device: RegisteredDevice,
    device_secret: String,
    rustdesk_server: RustdeskServer,
    /// 后台分配的设备名（如“春熙路店1号机”）
    name: Option<String>,
    /// 门店名称
    store_name: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegisteredDevice {
    id: i32,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RustdeskServer {
    id_server: String,
    relay_server: String,
    public_key: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HeartbeatRequest {
    rustdesk_id: String,
    hostname: String,
    operating_system: String,
    client_version: String,
    engine_instance_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreatePairingRequest {
    device_uuid: String,
    rustdesk_id: String,
    name: String,
    hostname: String,
    operating_system: String,
    client_version: String,
    rebind_code: String,
    rebind_authorization: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreatePairingResponse {
    pairing: CreatedPairing,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreatedPairing {
    id: i32,
    pairing_secret: String,
    device_secret: String,
    binding_code: String,
    bind_url: String,
    expires_at: String,
    rebind_authorization: Option<String>,
    rebind_authorization_expires_at: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PairingStatusResponse {
    status: String,
    expires_at: Option<String>,
    device: Option<PairingBoundDevice>,
    store: Option<PairingBoundStore>,
    rustdesk_server: Option<RustdeskServer>,
}

#[derive(Deserialize)]
struct PairingBoundDevice {
    id: i32,
    name: Option<String>,
    #[serde(rename = "rustdeskId")]
    rustdesk_id: String,
}

#[derive(Deserialize)]
struct PairingBoundStore {
    name: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PairingDisplay {
    status: String,
    binding_code: Option<String>,
    bind_url: Option<String>,
    expires_at: Option<String>,
    device_name: Option<String>,
    store_name: Option<String>,
    rustdesk_id: Option<String>,
    rebind_authorization_expires_at: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionInstanceRequest {
    engine_instance_id: String,
}

#[derive(Deserialize)]
struct ActiveSessionResponse {
    session: Option<ActiveSessionResponseItem>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ActiveSessionResponseItem {
    id: i32,
    access_key: String,
    expires_at: String,
    #[serde(default)]
    connected: bool,
}

fn api_base_url() -> Result<String, String> {
    let configured = Config::get_option(API_BASE_URL_OPTION);
    let value = if configured.trim().is_empty() {
        option_env!("CASHIER_API_BASE_URL")
            .filter(|value| !value.trim().is_empty())
            .unwrap_or("http://localhost:3000")
    } else {
        configured.trim()
    };
    let value = value
        .trim_end_matches('/')
        .to_owned();
    let parsed = url::Url::parse(&value).map_err(|_| "管理后台网址格式不正确".to_owned())?;
    let is_local = matches!(parsed.host_str(), Some("localhost" | "127.0.0.1" | "::1"));
    if parsed.scheme() != "https" && !(parsed.scheme() == "http" && is_local) {
        return Err("管理后台必须使用 HTTPS 安全网址".to_owned());
    }
    Ok(value)
}

fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "Cashier".to_owned())
}

fn operating_system() -> String {
    std::env::consts::OS.to_owned()
}

fn device_uuid() -> String {
    // 持久化设备唯一编号：重装/重新登记时复用同一编号，
    // 后台会更新原设备记录而不是新建（重装不重号）。
    let saved = Config::get_option(DEVICE_UUID_OPTION);
    if !saved.is_empty() {
        return saved;
    }
    let uuid = crate::encode64(hbb_common::get_uuid());
    Config::set_option(DEVICE_UUID_OPTION.to_owned(), uuid.clone());
    uuid
}

fn credentials() -> Option<DeviceCredential> {
    let id = Config::get_option(DEVICE_ID_OPTION).parse::<i32>().ok()?;
    let encrypted = Config::get_option(DEVICE_SECRET_OPTION);
    if encrypted.is_empty() {
        return None;
    }
    let (secret, decrypted, _) =
        decrypt_str_or_original(&encrypted, SECRET_ENCRYPTION_VERSION);
    if !decrypted || secret.is_empty() {
        log::error!("Failed to decrypt cashier remote device credential");
        return None;
    }
    Some(DeviceCredential { id, secret })
}

fn save_registration(
    device_id: i32,
    encrypted_device_secret: String,
    server: &RustdeskServer,
) -> Result<(), String> {
    let mut options = crate::ipc::get_options();
    options.insert(DEVICE_ID_OPTION.to_owned(), device_id.to_string());
    options.insert(DEVICE_SECRET_OPTION.to_owned(), encrypted_device_secret);
    options.insert(
        "custom-rendezvous-server".to_owned(),
        server.id_server.clone(),
    );
    if server.relay_server.is_empty() {
        options.remove("relay-server");
    } else {
        options.insert("relay-server".to_owned(), server.relay_server.clone());
    }
    options.insert("key".to_owned(), server.public_key.clone());
    crate::ipc::set_options(options).map_err(|err| format!("无法保存设备登记信息：{err}"))
}

/// Clear only the backend-issued device credentials after the backend has
/// authoritatively rejected them. Keep the stable device UUID so a later
/// pairing still identifies this physical computer consistently.
pub fn clear_registration() -> Result<String, String> {
    let mut options = crate::ipc::get_options();
    options.remove(DEVICE_ID_OPTION);
    options.remove(DEVICE_SECRET_OPTION);
    options.remove(PAIRING_ID_OPTION);
    options.remove(PAIRING_SECRET_OPTION);
    options.remove(PAIRING_DEVICE_SECRET_OPTION);
    options.remove(REBIND_AUTHORIZATION_OPTION);
    options.remove(REBIND_AUTHORIZATION_EXPIRES_AT_OPTION);
    crate::ipc::set_options(options)
        .map_err(|err| format!("无法清除设备登记信息：{err}"))?;
    ACTIVE_SESSION.lock().unwrap().take();
    CONSUMED_SESSION_ID.lock().unwrap().take();
    Ok("设备登记信息已清除".to_owned())
}

/// 将助手内置的私有服务器配置同步到当前 RustDesk 配置及已运行的服务。
/// 这条命令用于修复升级/重装后残留的旧服务器地址或旧公钥。
pub fn sync_server_config() -> Result<String, String> {
    let mut options = crate::ipc::get_options();
    options.insert(
        "custom-rendezvous-server".to_owned(),
        FIXED_ID_SERVER.to_owned(),
    );
    options.insert("relay-server".to_owned(), FIXED_RELAY_SERVER.to_owned());
    options.insert("key".to_owned(), FIXED_PUBLIC_KEY.to_owned());
    crate::ipc::set_options(options)
        .map_err(|err| format!("无法同步远程服务器配置：{err}"))?;
    Ok("远程服务器配置已同步".to_owned())
}

fn encrypt_pending_secret(value: &str) -> Result<String, String> {
    let encrypted = encrypt_str_or_original(value, SECRET_ENCRYPTION_VERSION, SECRET_MAX_LEN);
    if encrypted == value {
        return Err("设备绑定凭证加密失败".to_owned());
    }
    Ok(encrypted)
}

fn decrypt_pending_secret(option: &str) -> Result<String, String> {
    let encrypted = Config::get_option(option);
    if encrypted.is_empty() {
        return Err("本机没有等待确认的绑定申请".to_owned());
    }
    let (value, decrypted, _) = decrypt_str_or_original(&encrypted, SECRET_ENCRYPTION_VERSION);
    if !decrypted || value.is_empty() {
        return Err("无法读取本机绑定凭证，请重新生成二维码".to_owned());
    }
    Ok(value)
}

fn decrypt_optional_secret(option: &str) -> String {
    let encrypted = Config::get_option(option);
    if encrypted.is_empty() {
        return String::new();
    }
    let (value, decrypted, _) =
        decrypt_str_or_original(&encrypted, SECRET_ENCRYPTION_VERSION);
    if decrypted {
        value
    } else {
        log::error!("Failed to decrypt optional cashier authorization");
        String::new()
    }
}

fn clear_pairing_options() -> Result<(), String> {
    let mut options = crate::ipc::get_options();
    options.remove(PAIRING_ID_OPTION);
    options.remove(PAIRING_SECRET_OPTION);
    options.remove(PAIRING_DEVICE_SECRET_OPTION);
    crate::ipc::set_options(options).map_err(|err| format!("无法清理绑定申请：{err}"))
}

fn response_error(prefix: &str, response: reqwest::blocking::Response) -> String {
    let status = response.status();
    let detail = response
        .json::<serde_json::Value>()
        .ok()
        .and_then(|json| json["message"].as_str().map(str::to_owned));
    detail
        .map(|message| format!("{prefix}：{message}"))
        .unwrap_or_else(|| format!("{prefix}，后台返回状态码 {status}"))
}

pub fn create_pairing(qr_path: &str, rebind_code: &str) -> Result<String, String> {
    let rustdesk_id = Config::get_id();
    if rustdesk_id.trim().len() < 6 {
        return Err("远程引擎尚未取得设备 ID，请稍后重试".to_owned());
    }

    let rebind_authorization = if rebind_code.trim().is_empty() {
        decrypt_optional_secret(REBIND_AUTHORIZATION_OPTION)
    } else {
        String::new()
    };
    let request = CreatePairingRequest {
        device_uuid: device_uuid(),
        rustdesk_id,
        name: hostname(),
        hostname: hostname(),
        operating_system: operating_system(),
        client_version: crate::VERSION.to_owned(),
        rebind_code: rebind_code.trim().to_owned(),
        rebind_authorization,
    };
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|err| format!("无法创建网络连接：{err}"))?;
    let response = client
        .post(format!("{}/remote/client/pairings", api_base_url()?))
        .json(&request)
        .send()
        .map_err(|err| format!("无法连接管理后台：{err}"))?;
    if !response.status().is_success() {
        return Err(response_error("生成设备绑定码失败", response));
    }
    let response = response
        .json::<CreatePairingResponse>()
        .map_err(|err| format!("无法读取后台绑定结果：{err}"))?;

    let encrypted_pairing_secret = encrypt_pending_secret(&response.pairing.pairing_secret)?;
    let encrypted_device_secret = encrypt_pending_secret(&response.pairing.device_secret)?;
    let mut options = crate::ipc::get_options();
    options.insert(PAIRING_ID_OPTION.to_owned(), response.pairing.id.to_string());
    options.insert(PAIRING_SECRET_OPTION.to_owned(), encrypted_pairing_secret);
    options.insert(
        PAIRING_DEVICE_SECRET_OPTION.to_owned(),
        encrypted_device_secret,
    );
    if let Some(authorization) = response.pairing.rebind_authorization.as_deref() {
        options.insert(
            REBIND_AUTHORIZATION_OPTION.to_owned(),
            encrypt_pending_secret(authorization)?,
        );
    }
    if let Some(expires_at) = response
        .pairing
        .rebind_authorization_expires_at
        .as_deref()
    {
        options.insert(
            REBIND_AUTHORIZATION_EXPIRES_AT_OPTION.to_owned(),
            expires_at.to_owned(),
        );
    }
    crate::ipc::set_options(options)
        .map_err(|err| format!("无法保存设备绑定申请：{err}"))?;

    if !qr_path.trim().is_empty() {
        let png = qrcode_generator::to_png_to_vec(
            response.pairing.bind_url.as_bytes(),
            qrcode_generator::QrCodeEcc::Medium,
            240,
        )
        .map_err(|err| format!("二维码生成失败：{err}"))?;
        std::fs::write(qr_path, png).map_err(|err| format!("二维码保存失败：{err}"))?;
    }

    serde_json::to_string(&PairingDisplay {
        status: "pending".to_owned(),
        binding_code: Some(response.pairing.binding_code),
        bind_url: Some(response.pairing.bind_url),
        expires_at: Some(response.pairing.expires_at),
        device_name: None,
        store_name: None,
        rustdesk_id: None,
        rebind_authorization_expires_at: response
            .pairing
            .rebind_authorization_expires_at,
    })
    .map_err(|err| err.to_string())
}

pub fn pairing_status() -> Result<String, String> {
    let pairing_id = Config::get_option(PAIRING_ID_OPTION)
        .parse::<i32>()
        .map_err(|_| "本机没有等待确认的绑定申请".to_owned())?;
    let pairing_secret = decrypt_pending_secret(PAIRING_SECRET_OPTION)?;
    let device_secret = decrypt_pending_secret(PAIRING_DEVICE_SECRET_OPTION)?;
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|err| format!("无法创建网络连接：{err}"))?;
    let response = client
        .get(format!(
            "{}/remote/client/pairings/{pairing_id}/status",
            api_base_url()?
        ))
        .header("x-pairing-secret", pairing_secret)
        .send()
        .map_err(|err| format!("无法连接管理后台：{err}"))?;
    if !response.status().is_success() {
        return Err(response_error("查询设备绑定状态失败", response));
    }
    let response = response
        .json::<PairingStatusResponse>()
        .map_err(|err| format!("无法读取设备绑定状态：{err}"))?;

    if response.status == "bound" {
        let device = response.device.ok_or_else(|| "后台缺少绑定设备信息".to_owned())?;
        let server = response
            .rustdesk_server
            .ok_or_else(|| "后台缺少远程服务器配置".to_owned())?;
        let encrypted = encrypt_pending_secret(&device_secret)?;
        save_registration(device.id, encrypted, &server)?;
        let mut options = crate::ipc::get_options();
        options.remove(REBIND_AUTHORIZATION_OPTION);
        options.remove(REBIND_AUTHORIZATION_EXPIRES_AT_OPTION);
        crate::ipc::set_options(options)
            .map_err(|err| format!("无法清理换绑授权：{err}"))?;
        clear_pairing_options()?;
        return serde_json::to_string(&PairingDisplay {
            status: "bound".to_owned(),
            binding_code: None,
            bind_url: None,
            expires_at: None,
            device_name: device.name,
            store_name: response.store.map(|store| store.name),
            rustdesk_id: Some(device.rustdesk_id),
            rebind_authorization_expires_at: None,
        })
        .map_err(|err| err.to_string());
    }

    if matches!(response.status.as_str(), "expired" | "cancelled") {
        clear_pairing_options()?;
    }
    serde_json::to_string(&PairingDisplay {
        status: response.status,
        binding_code: None,
        bind_url: None,
        expires_at: response.expires_at,
        device_name: None,
        store_name: None,
        rustdesk_id: None,
        rebind_authorization_expires_at: {
            let value = Config::get_option(REBIND_AUTHORIZATION_EXPIRES_AT_OPTION);
            if value.is_empty() { None } else { Some(value) }
        },
    })
    .map_err(|err| err.to_string())
}

pub fn enroll(enrollment_token: &str, device_name: &str) -> Result<String, String> {
    let enrollment_token = enrollment_token.trim();
    if enrollment_token.is_empty() {
        return Err("安装码不能为空".to_owned());
    }

    // 绑定人员填写的设备名优先，未填则用计算机名
    let name = if device_name.trim().is_empty() {
        hostname()
    } else {
        device_name.trim().to_owned()
    };

    let request = RegisterRequest {
        enrollment_token: enrollment_token.to_owned(),
        device_uuid: device_uuid(),
        rustdesk_id: Config::get_id(),
        name: name.clone(),
        hostname: hostname(),
        operating_system: operating_system(),
        client_version: crate::VERSION.to_owned(),
    };
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|err| format!("无法创建网络连接：{err}"))?;
    let response = client
        .post(format!("{}/remote/client/register", api_base_url()?))
        .json(&request)
        .send()
        .map_err(|err| format!("无法连接管理后台：{err}"))?;

    if !response.status().is_success() {
        return Err(format!("设备登记失败，后台返回状态码 {}", response.status()));
    }

    let response = response
        .json::<RegisterResponse>()
        .map_err(|err| format!("无法读取后台返回结果：{err}"))?;
    let encrypted = encrypt_str_or_original(
        &response.device_secret,
        SECRET_ENCRYPTION_VERSION,
        SECRET_MAX_LEN,
    );
    if encrypted == response.device_secret {
        return Err("设备密钥加密失败，未保存登记信息".to_owned());
    }

    save_registration(response.device.id, encrypted, &response.rustdesk_server)?;

    let assigned_name = response
        .name
        .filter(|value| !value.trim().is_empty())
        .or_else(|| response.store_name.filter(|value| !value.trim().is_empty()));
    let suffix = assigned_name
        .map(|value| format!("，设备：{}", value.trim()))
        .unwrap_or_default();

    Ok(format!(
        "设备登记成功，RustDesk ID：{}{}",
        Config::get_id(),
        suffix
    ))
}

/// 打印本机在后台登记的设备名和门店名（助手轮询门店名用）。
pub fn print_device_name() -> Result<String, String> {
    let Some(credential) = credentials() else {
        return Err("本机尚未登记".to_owned());
    };
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|err| err.to_string())?;
    let response = client
        .get(format!("{}/remote/client/me", api_base_url()?))
        .header("x-remote-device-id", credential.id.to_string())
        .header("x-remote-device-secret", &credential.secret)
        .send()
        .map_err(|err| format!("无法连接管理后台：{err}"))?;
    if !response.status().is_success() {
        return Err(format!("后台返回状态码 {}", response.status()));
    }
    let json: serde_json::Value = response
        .json()
        .map_err(|err| format!("无法读取后台返回结果：{err}"))?;
    let device_name = json["device"]["name"]
        .as_str()
        .unwrap_or("")
        .trim()
        .to_owned();
    let store_name = json["store"]["name"]
        .as_str()
        .unwrap_or("")
        .trim()
        .to_owned();
    if device_name.is_empty() && store_name.is_empty() {
        return Err("后台没有该设备的信息".to_owned());
    }
    Ok(format!("设备：{}，门店：{}", device_name, store_name))
}

fn authenticated_request(
    client: &reqwest::Client,
    method: reqwest::Method,
    path: &str,
    credential: &DeviceCredential,
) -> Result<reqwest::RequestBuilder, String> {
    Ok(client
        .request(method, format!("{}{}", api_base_url()?, path))
        .header("x-remote-device-id", credential.id.to_string())
        .header("x-remote-device-secret", &credential.secret))
}

fn async_http_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|err| err.to_string())
}

async fn heartbeat(
    client: &reqwest::Client,
    credential: &DeviceCredential,
) -> Result<(), String> {
    let body = HeartbeatRequest {
        rustdesk_id: Config::get_id(),
        hostname: hostname(),
        operating_system: operating_system(),
        client_version: crate::VERSION.to_owned(),
        engine_instance_id: ENGINE_INSTANCE_ID.clone(),
    };
    let response = authenticated_request(
        client,
        reqwest::Method::POST,
        "/remote/client/heartbeat",
        credential,
    )?
    .json(&body)
    .send()
    .await
    .map_err(|err| err.to_string())?;
    if !response.status().is_success() {
        return Err(format!("heartbeat returned {}", response.status()));
    }
    Ok(())
}

/// Query the authenticated, heartbeat-validated session notice without
/// exposing the device secret to the desktop assistant process.
pub fn print_session_notice() -> Result<String, String> {
    let Some(credential) = credentials() else {
        return Err("本机尚未登记".to_owned());
    };
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|err| err.to_string())?;
    let response = client
        .get(format!("{}/remote/client/sessions/notice", api_base_url()?))
        .header("x-remote-device-id", credential.id.to_string())
        .header("x-remote-device-secret", &credential.secret)
        .send()
        .map_err(|err| format!("无法连接管理后台：{err}"))?;
    if !response.status().is_success() {
        return Err(format!("后台返回状态码 {}", response.status()));
    }
    response.text().map_err(|err| format!("无法读取后台返回结果：{err}"))
}

/// End a session through the authenticated engine credential. The assistant
/// invokes this command and never reads or stores the device secret itself.
pub fn end_session_from_assistant(session_id: i32) -> Result<String, String> {
    let Some(credential) = credentials() else {
        return Err("本机尚未登记".to_owned());
    };
    if session_id <= 0 {
        return Err("远程会话编号无效".to_owned());
    }
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|err| err.to_string())?;
    let response = client
        .post(format!(
            "{}/remote/client/sessions/{session_id}/end",
            api_base_url()?
        ))
        .header("x-remote-device-id", credential.id.to_string())
        .header("x-remote-device-secret", &credential.secret)
        .json(&serde_json::json!({ "reason": "customer_disconnect" }))
        .send()
        .map_err(|err| format!("无法连接管理后台：{err}"))?;
    if !response.status().is_success() {
        return Err(format!("后台返回状态码 {}", response.status()));
    }
    Ok("远程会话已结束".to_owned())
}

async fn poll_active_session(
    client: &reqwest::Client,
    credential: &DeviceCredential,
) -> Result<(), String> {
    let response = authenticated_request(
        client,
        reqwest::Method::GET,
        "/remote/client/sessions/active",
        credential,
    )?
    .send()
    .await
    .map_err(|err| err.to_string())?;
    if !response.status().is_success() {
        let status = response.status();
        if matches!(
            status,
            reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN
        ) {
            ACTIVE_SESSION.lock().unwrap().take();
            CONSUMED_SESSION_ID.lock().unwrap().take();
        }
        return Err(format!("session poll returned {status}"));
    }
    let response = response
        .json::<ActiveSessionResponse>()
        .await
        .map_err(|err| err.to_string())?;
    let session = response.session.and_then(|session| {
        let expires_at = chrono::DateTime::parse_from_rfc3339(&session.expires_at)
            .ok()?
            .timestamp();
        Some(ActiveSession {
            id: session.id,
            access_key: session.access_key,
            expires_at,
            connected: session.connected,
        })
    });
    let mut active_session = ACTIVE_SESSION.lock().unwrap();
    let mut consumed_session_id = CONSUMED_SESSION_ID.lock().unwrap();
    match session {
        // A connected backend session may only be resumed by the same engine
        // process that authenticated its primary remote-control connection.
        Some(session)
            if session.connected && *consumed_session_id != Some(session.id) =>
        {
            active_session.take();
        }
        Some(session) => {
            if *consumed_session_id != Some(session.id) {
                consumed_session_id.take();
            }
            *active_session = Some(session);
        }
        None => {
            active_session.take();
            consumed_session_id.take();
        }
    }
    Ok(())
}

/// 是否为果次方定制构建（编译期内置了管理后台地址）。
pub fn is_cashier_build() -> bool {
    option_env!("CASHIER_API_BASE_URL").is_some()
}

pub fn start_host_agent() {
    static START: Once = Once::new();
    START.call_once(|| {
        tokio::spawn(async {
            let client = match async_http_client() {
                Ok(client) => client,
                Err(err) => {
                    log::error!("Failed to start cashier remote HTTP client: {err}");
                    return;
                }
            };
            let mut heartbeat_timer = tokio::time::interval(HEARTBEAT_INTERVAL);
            let mut poll_timer = tokio::time::interval(SESSION_POLL_INTERVAL);
            let mut session_heartbeat_timer =
                tokio::time::interval(SESSION_HEARTBEAT_INTERVAL);
            loop {
                tokio::select! {
                    _ = heartbeat_timer.tick() => {
                        let Some(credential) = credentials() else {
                            continue;
                        };
                        if let Err(err) = heartbeat(&client, &credential).await {
                            log::warn!("Cashier remote heartbeat failed: {err}");
                        }
                    }
                    _ = poll_timer.tick() => {
                        let Some(credential) = credentials() else {
                            continue;
                        };
                        if let Err(err) = poll_active_session(&client, &credential).await {
                            log::warn!("Cashier remote session poll failed: {err}");
                        }
                    }
                    _ = session_heartbeat_timer.tick() => {
                        let session_id = *CONSUMED_SESSION_ID.lock().unwrap();
                        if let Some(session_id) = session_id {
                            if let Err(err) = send_session_status(session_id, "heartbeat").await {
                                log::warn!("Cashier remote session heartbeat failed: {err}");
                            }
                        }
                    }
                }
            }
        });
    });
}

/// Refresh the active session from the backend right before a login attempt,
/// so the very first connection after a disconnect is not rejected due to the
/// 1s polling gap.
pub async fn refresh_active_session() {
    let Some(credential) = credentials() else {
        return;
    };
    let Ok(client) = async_http_client() else {
        return;
    };
    let _ = poll_active_session(&client, &credential).await;
}

pub fn validate_access_key<F>(
    allow_connected_file_transfer: bool,
    matches: F,
) -> Option<i32>
where
    F: FnOnce(&str) -> bool,
{
    let mut active_session = ACTIVE_SESSION.lock().unwrap();
    let Some(session) = active_session.as_ref() else {
        return None;
    };
    if !session.connected && session.expires_at <= chrono::Utc::now().timestamp() {
        active_session.take();
        return None;
    }
    let consumed_session_id = *CONSUMED_SESSION_ID.lock().unwrap();
    let scope_allowed = match consumed_session_id {
        Some(consumed_id) => allow_connected_file_transfer && consumed_id == session.id,
        None => !allow_connected_file_transfer,
    };
    (scope_allowed && matches(&session.access_key)).then_some(session.id)
}

pub fn authorize_access_key(session_id: i32, is_file_transfer: bool) -> bool {
    let active_session = ACTIVE_SESSION.lock().unwrap();
    let Some(session) = active_session.as_ref() else {
        return false;
    };
    if session.id != session_id
        || (!session.connected && session.expires_at <= chrono::Utc::now().timestamp())
    {
        return false;
    }
    let mut consumed_session_id = CONSUMED_SESSION_ID.lock().unwrap();
    match *consumed_session_id {
        Some(consumed_id) => is_file_transfer && consumed_id == session_id,
        None if !is_file_transfer => {
            *consumed_session_id = Some(session_id);
            true
        }
        None => false,
    }
}

pub fn clear_session(session_id: i32) {
    let mut active_session = ACTIVE_SESSION.lock().unwrap();
    let mut consumed_session_id = CONSUMED_SESSION_ID.lock().unwrap();
    if *consumed_session_id == Some(session_id) {
        consumed_session_id.take();
        if active_session.as_ref().map(|session| session.id) == Some(session_id) {
            active_session.take();
        }
    }
}

pub fn is_registered() -> bool {
    credentials().is_some()
}

pub fn is_session_active(session_id: i32) -> bool {
    ACTIVE_SESSION.lock().unwrap().as_ref().map(|session| session.id)
        == Some(session_id)
        && *CONSUMED_SESSION_ID.lock().unwrap() == Some(session_id)
}

async fn send_session_status(session_id: i32, action: &str) -> Result<(), String> {
    let Some(credential) = credentials() else {
        return Err("device credential is missing".to_owned());
    };
    let client = async_http_client()?;
    let path = format!("/remote/client/sessions/{session_id}/{action}");
    let response = authenticated_request(
        &client,
        reqwest::Method::POST,
        &path,
        &credential,
    )?
    .json(&SessionInstanceRequest {
        engine_instance_id: ENGINE_INSTANCE_ID.clone(),
    })
    .send()
    .await
    .map_err(|err| err.to_string())?;
    if !response.status().is_success() {
        return Err(format!("session {action} returned {}", response.status()));
    }
    Ok(())
}

fn report_session_status(session_id: i32, action: &'static str) {
    tokio::spawn(async move {
        if let Err(err) = send_session_status(session_id, action).await {
            log::warn!("Cashier remote session {action} failed: {err}");
        }
    });
}

pub fn report_connected(session_id: i32) {
    report_session_status(session_id, "connected");
}

pub fn report_ended(session_id: i32) {
    report_session_status(session_id, "end");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_key_only_allows_file_transfer_after_primary_connection() {
        *CONSUMED_SESSION_ID.lock().unwrap() = None;
        *ACTIVE_SESSION.lock().unwrap() = Some(ActiveSession {
            id: 7,
            access_key: "one-time-key".to_owned(),
            expires_at: chrono::Utc::now().timestamp() + 60,
            connected: false,
        });

        assert_eq!(
            validate_access_key(false, |value| value == "one-time-key"),
            Some(7)
        );
        assert!(authorize_access_key(7, false));
        assert!(!authorize_access_key(7, false));
        assert_eq!(
            validate_access_key(true, |value| value == "one-time-key"),
            Some(7)
        );
        assert!(authorize_access_key(7, true));
        assert!(authorize_access_key(7, true));

        clear_session(7);
        assert!(
            validate_access_key(true, |value| value == "one-time-key").is_none()
        );

        *ACTIVE_SESSION.lock().unwrap() = Some(ActiveSession {
            id: 8,
            access_key: "expired-key".to_owned(),
            expires_at: chrono::Utc::now().timestamp() - 1,
            connected: false,
        });
        assert!(
            validate_access_key(false, |value| value == "expired-key").is_none()
        );

        *CONSUMED_SESSION_ID.lock().unwrap() = Some(9);
        *ACTIVE_SESSION.lock().unwrap() = Some(ActiveSession {
            id: 9,
            access_key: "connected-key".to_owned(),
            expires_at: chrono::Utc::now().timestamp() - 60,
            connected: true,
        });

        assert_eq!(
            validate_access_key(true, |value| value == "connected-key"),
            Some(9)
        );
        assert!(authorize_access_key(9, true));
        assert!(!authorize_access_key(9, false));
        clear_session(9);
        *CONSUMED_SESSION_ID.lock().unwrap() = None;
    }
}
