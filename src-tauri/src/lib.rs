use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::PathBuf,
    sync::Mutex,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tauri::{AppHandle, Manager, State};
use totp_rs::{Algorithm, Builder, Secret, Totp};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct Account {
    id: String,
    name: String,
    secret: String,
}

#[derive(Serialize)]
struct AccountLabel {
    id: String,
    name: String,
}

#[derive(Serialize)]
struct AccountCode {
    id: String,
    code: String,
    remaining: u64,
}

#[derive(Default)]
struct AuthSession {
    verified_at: Mutex<Option<Instant>>,
    quick_secret: Mutex<Option<String>>,
}

impl Drop for AuthSession {
    fn drop(&mut self) {
        if let Ok(secret) = self.quick_secret.get_mut() {
            if let Some(value) = secret.as_mut() {
                value.zeroize();
            }
        }
    }
}

fn ensure_unlocked(session: &AuthSession) -> Result<(), String> {
    let verified_at = session
        .verified_at
        .lock()
        .map_err(|_| "Не удалось проверить сессию".to_string())?;
    if verified_at.is_some_and(|time| time.elapsed() < Duration::from_secs(60 * 60)) {
        Ok(())
    } else {
        if let Ok(mut secret) = session.quick_secret.lock() {
            if let Some(mut value) = secret.take() {
                value.zeroize();
            }
        }
        Err("Сессия истекла. Подтвердите вход через Windows Hello.".into())
    }
}

fn data_path(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir.join("vault.dat"))
}

fn protect(bytes: &[u8]) -> Result<Vec<u8>, String> {
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::Cryptography::{CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData},
    };
    let input = CRYPT_INTEGER_BLOB {
        cbData: bytes.len() as u32,
        pbData: bytes.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    let ok = unsafe {
        CryptProtectData(
            &input,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 {
        return Err("Windows не смог зашифровать хранилище".into());
    }
    let encrypted =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) }.to_vec();
    unsafe {
        LocalFree(output.pbData as *mut _);
    }
    Ok(encrypted)
}

fn unprotect(bytes: &[u8]) -> Result<Vec<u8>, String> {
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::Cryptography::{
            CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptUnprotectData,
        },
    };
    let input = CRYPT_INTEGER_BLOB {
        cbData: bytes.len() as u32,
        pbData: bytes.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    let ok = unsafe {
        CryptUnprotectData(
            &input,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 {
        return Err(
            "Не удалось открыть хранилище Windows. Проверьте учётную запись пользователя.".into(),
        );
    }
    let plaintext =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) }.to_vec();
    unsafe {
        std::ptr::write_bytes(output.pbData, 0, output.cbData as usize);
        LocalFree(output.pbData as *mut _);
    }
    Ok(plaintext)
}

fn load_accounts(app: &AppHandle) -> Result<Vec<Account>, String> {
    let path = data_path(app)?;
    if !path.exists() {
        return Ok(Vec::new());
    }
    let encrypted = fs::read(path).map_err(|e| e.to_string())?;
    let mut plaintext = unprotect(&encrypted)?;
    let parsed =
        serde_json::from_slice(&plaintext).map_err(|e| format!("Хранилище повреждено: {e}"));
    plaintext.zeroize();
    parsed
}

fn save_accounts(app: &AppHandle, accounts: &[Account]) -> Result<(), String> {
    let path = data_path(app)?;
    let mut plaintext = serde_json::to_vec(accounts).map_err(|e| e.to_string())?;
    let encrypted = protect(&plaintext);
    plaintext.zeroize();
    let encrypted = encrypted?;
    let temp = path.with_extension("tmp");
    fs::write(&temp, encrypted).map_err(|e| e.to_string())?;
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::{
            MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
        };
        let from = temp
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let to = path
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let ok = unsafe {
            MoveFileExW(
                from.as_ptr(),
                to.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        };
        if ok == 0 {
            return Err("Не удалось сохранить зашифрованное хранилище".into());
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        fs::rename(temp, path).map_err(|e| e.to_string())
    }
}

fn totp(secret: &str) -> Result<Totp, String> {
    let mut cleaned = secret
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect::<String>()
        .to_ascii_uppercase();
    let parsed_secret = Secret::try_from_base32(&cleaned);
    cleaned.zeroize();
    let secret =
        parsed_secret.map_err(|_| "Проверьте секрет: нужен ключ в формате Base32".to_string())?;
    Builder::new()
        .with_algorithm(Algorithm::SHA1)
        .with_digits(6)
        .with_step_duration(30)
        .with_secret(secret)
        .build()
        .map_err(|e| format!("Не удалось создать код: {e}"))
}

#[tauri::command]
async fn verify_hello(app: AppHandle, session: State<'_, AuthSession>) -> Result<(), String> {
    use windows::Security::Credentials::UI::{
        UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability,
    };
    use windows::Win32::System::WinRT::{IUserConsentVerifierInterop, RoGetActivationFactory};
    use windows::core::HSTRING;
    if let Ok(mut secret) = session.quick_secret.lock() {
        if let Some(mut value) = secret.take() {
            value.zeroize();
        }
    }
    let availability = UserConsentVerifier::CheckAvailabilityAsync()
        .map_err(|e| format!("Windows Hello недоступен: {e}"))?
        .await
        .map_err(|e| format!("Не удалось проверить Windows Hello: {e}"))?;
    if availability != UserConsentVerifierAvailability::Available {
        return Err("Windows Hello не настроен. Включите его в Параметрах Windows → Учётные записи → Варианты входа, затем перезапустите приложение.".into());
    }
    let window = app
        .get_webview_window("main")
        .ok_or_else(|| "Окно приложения не найдено".to_string())?;
    let hwnd = window.hwnd().map_err(|e| e.to_string())?;
    let message = HSTRING::from("Подтвердите вход в 2FA Manager");
    let operation: windows_future::IAsyncOperation<UserConsentVerificationResult> = {
        let verifier: IUserConsentVerifierInterop = unsafe {
            RoGetActivationFactory(&HSTRING::from(
                "Windows.Security.Credentials.UI.UserConsentVerifier",
            ))
        }
        .map_err(|e| format!("Не удалось открыть Windows Hello: {e}"))?;
        unsafe { verifier.RequestVerificationForWindowAsync(hwnd, &message) }
            .map_err(|e| e.to_string())?
    };
    let result = operation.await.map_err(|e| e.to_string())?;
    if result == UserConsentVerificationResult::Verified {
        *session
            .verified_at
            .lock()
            .map_err(|_| "Не удалось сохранить состояние входа".to_string())? =
            Some(Instant::now());
        Ok(())
    } else {
        Err("Проверка Windows Hello не пройдена. Повторите попытку.".into())
    }
}

#[tauri::command]
fn list_accounts(
    app: AppHandle,
    session: State<'_, AuthSession>,
) -> Result<Vec<AccountLabel>, String> {
    ensure_unlocked(&session)?;
    let accounts = load_accounts(&app)?;
    Ok(accounts
        .iter()
        .map(|a| AccountLabel {
            id: a.id.clone(),
            name: a.name.clone(),
        })
        .collect())
}

#[tauri::command]
fn list_codes(app: AppHandle, session: State<'_, AuthSession>) -> Result<Vec<AccountCode>, String> {
    ensure_unlocked(&session)?;
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();
    load_accounts(&app)?
        .into_iter()
        .map(|a| {
            let code = totp(&a.secret)?.generate(seconds).to_string();
            Ok(AccountCode {
                id: a.id.clone(),
                code,
                remaining: 30 - seconds % 30,
            })
        })
        .collect()
}

#[tauri::command]
fn generate_code(
    session: State<'_, AuthSession>,
    mut secret: String,
) -> Result<AccountCode, String> {
    ensure_unlocked(&session)?;
    let mut stored = session
        .quick_secret
        .lock()
        .map_err(|_| "Не удалось обновить временный секрет".to_string())?;
    if let Some(mut old) = stored.take() {
        old.zeroize();
    }
    drop(stored);
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();
    let generated = match totp(&secret) {
        Ok(totp) => totp,
        Err(error) => {
            secret.zeroize();
            return Err(error);
        }
    };
    let normalized = secret
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect::<String>()
        .to_ascii_uppercase();
    secret.zeroize();
    let mut stored = session
        .quick_secret
        .lock()
        .map_err(|_| "Не удалось сохранить секрет для обновления кода".to_string())?;
    if let Some(mut old) = stored.replace(normalized) {
        old.zeroize();
    }
    drop(stored);
    let code = generated.generate(seconds).to_string();
    Ok(AccountCode {
        id: "quick".into(),
        code,
        remaining: 30 - seconds % 30,
    })
}

#[tauri::command]
fn refresh_quick_code(session: State<'_, AuthSession>) -> Result<Option<AccountCode>, String> {
    ensure_unlocked(&session)?;
    let stored = session
        .quick_secret
        .lock()
        .map_err(|_| "Не удалось прочитать секрет".to_string())?;
    let Some(secret) = stored.as_ref() else {
        return Ok(None);
    };
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();
    let code = totp(secret)?.generate(seconds).to_string();
    Ok(Some(AccountCode {
        id: "quick".into(),
        code,
        remaining: 30 - seconds % 30,
    }))
}

#[tauri::command]
fn clear_quick_code(session: State<'_, AuthSession>) -> Result<(), String> {
    ensure_unlocked(&session)?;
    let mut stored = session
        .quick_secret
        .lock()
        .map_err(|_| "Не удалось удалить секрет".to_string())?;
    if let Some(mut secret) = stored.take() {
        secret.zeroize();
    }
    Ok(())
}

#[tauri::command]
fn add_account(
    app: AppHandle,
    session: State<'_, AuthSession>,
    name: String,
    mut secret: String,
) -> Result<(), String> {
    ensure_unlocked(&session)?;
    let name = name.trim();
    if name.is_empty() {
        secret.zeroize();
        return Err("Введите название аккаунта".into());
    }
    let mut cleaned = secret
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect::<String>()
        .to_ascii_uppercase();
    secret.zeroize();
    let valid = totp(&cleaned);
    if let Err(error) = valid {
        let mut cleaned = cleaned;
        cleaned.zeroize();
        return Err(error);
    }
    let mut accounts = match load_accounts(&app) {
        Ok(accounts) => accounts,
        Err(error) => {
            cleaned.zeroize();
            return Err(error);
        }
    };
    accounts.push(Account {
        id: Uuid::new_v4().to_string(),
        name: name.to_string(),
        secret: cleaned,
    });
    save_accounts(&app, &accounts)
}

#[tauri::command]
fn remove_account(
    app: AppHandle,
    session: State<'_, AuthSession>,
    id: String,
) -> Result<(), String> {
    ensure_unlocked(&session)?;
    let mut accounts = load_accounts(&app)?;
    accounts.retain(|a| a.id != id);
    save_accounts(&app, &accounts)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(AuthSession::default())
        .plugin(tauri_plugin_clipboard_manager::init())
        .invoke_handler(tauri::generate_handler![
            verify_hello,
            list_accounts,
            list_codes,
            generate_code,
            refresh_quick_code,
            clear_quick_code,
            add_account,
            remove_account
        ])
        .run(tauri::generate_context!())
        .expect("error while running Tauri application");
}
