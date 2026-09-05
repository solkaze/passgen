//! Windows専用: ファイルのACL（アクセス制御リスト）を検査する。
//! Unix版の chmod 600 検査（`seed::check_seed_permissions`）に相当する処理を、
//! NTFSのDACLに対して行う。「所有者・Administrators・SYSTEM」以外のアカウントに
//! アクセスを許可するACEが存在しないことを確認する。

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;

use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, ERROR_SUCCESS, HANDLE};
use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
use windows_sys::Win32::Security::{
    CreateWellKnownSid, EqualSid, GetAce, GetLengthSid, GetTokenInformation, ACCESS_ALLOWED_ACE,
    ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, INHERIT_ONLY_ACE, OWNER_SECURITY_INFORMATION,
    PSID, TOKEN_QUERY, TOKEN_USER, TokenUser, WinBuiltinAdministratorsSid, WinLocalSystemSid,
};
use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// ACL検査の結果、問題ありと判定された場合の種別。
pub enum AclProblem {
    /// DACLが存在しない（＝保護なし、全員アクセス可能）。
    NoDacl,
    /// 所有者・Administrators・SYSTEM 以外のアカウントにアクセスが許可されている。
    ExtraAccessGranted,
}

/// ACL検査自体が実行できなかった場合のエラー。
pub struct AclCheckError(pub String);

/// path のDACLが「所有者 + Administrators + SYSTEM」以外にアクセスを許可していないか検査する。
pub fn verify_owner_only(path: &Path) -> Result<Option<AclProblem>, AclCheckError> {
    unsafe { verify_owner_only_impl(path) }
}

struct LocalFreeGuard(*mut c_void);
impl Drop for LocalFreeGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0 as _);
            }
        }
    }
}

struct HandleGuard(HANDLE);
impl Drop for HandleGuard {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

unsafe fn verify_owner_only_impl(path: &Path) -> Result<Option<AclProblem>, AclCheckError> { unsafe {
    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut dacl: *mut ACL = ptr::null_mut();
    let mut sd: *mut c_void = ptr::null_mut();

    let status = GetNamedSecurityInfoW(
        wide.as_ptr(),
        SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        ptr::null_mut(),
        ptr::null_mut(),
        &mut dacl,
        ptr::null_mut(),
        &mut sd,
    );
    if status != ERROR_SUCCESS {
        return Err(AclCheckError(format!(
            "GetNamedSecurityInfoW に失敗しました (エラーコード: {})",
            status
        )));
    }
    let _sd_guard = LocalFreeGuard(sd);

    if dacl.is_null() {
        return Ok(Some(AclProblem::NoDacl));
    }

    let current_user_sid = current_process_user_sid()?;
    let admins_sid = well_known_sid(WinBuiltinAdministratorsSid)?;
    let system_sid = well_known_sid(WinLocalSystemSid)?;

    let ace_count = (*dacl).AceCount;
    for i in 0..ace_count as u32 {
        let mut ace_ptr: *mut c_void = ptr::null_mut();
        if GetAce(dacl, i, &mut ace_ptr) == 0 {
            return Err(AclCheckError("GetAce に失敗しました".to_string()));
        }

        let header = &*(ace_ptr as *const ACE_HEADER);
        if header.AceType as u32 != ACCESS_ALLOWED_ACE_TYPE {
            // DENY等の他種ACEは対象外（通常のファイルACLではACCESS_ALLOWEDのみを想定）
            continue;
        }
        if header.AceFlags & (INHERIT_ONLY_ACE as u8) != 0 {
            // 子オブジェクトにのみ継承されるACEで、このファイル自体への実効アクセス権ではない
            continue;
        }

        let ace = &*(ace_ptr as *const ACCESS_ALLOWED_ACE);
        let sid: PSID = &ace.SidStart as *const u32 as PSID;

        if EqualSid(sid, current_user_sid.as_ptr() as PSID) != 0 {
            continue;
        }
        if EqualSid(sid, admins_sid.as_ptr() as PSID) != 0 {
            continue;
        }
        if EqualSid(sid, system_sid.as_ptr() as PSID) != 0 {
            continue;
        }

        return Ok(Some(AclProblem::ExtraAccessGranted));
    }

    Ok(None)
}}

unsafe fn well_known_sid(sid_type: i32) -> Result<Vec<u8>, AclCheckError> { unsafe {
    let mut buf = vec![0u8; 256];
    let mut size = buf.len() as u32;
    if CreateWellKnownSid(sid_type, ptr::null_mut(), buf.as_mut_ptr() as PSID, &mut size) == 0 {
        return Err(AclCheckError("CreateWellKnownSid に失敗しました".to_string()));
    }
    buf.truncate(size as usize);
    Ok(buf)
}}

unsafe fn current_process_user_sid() -> Result<Vec<u8>, AclCheckError> { unsafe {
    let mut token: HANDLE = ptr::null_mut();
    if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
        return Err(AclCheckError("OpenProcessToken に失敗しました".to_string()));
    }
    let _token_guard = HandleGuard(token);

    let mut needed: u32 = 0;
    GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut needed);
    if needed == 0 {
        return Err(AclCheckError(
            "GetTokenInformation（サイズ取得）に失敗しました".to_string(),
        ));
    }

    let mut buf = vec![0u8; needed as usize];
    if GetTokenInformation(
        token,
        TokenUser,
        buf.as_mut_ptr() as *mut c_void,
        needed,
        &mut needed,
    ) == 0
    {
        return Err(AclCheckError("GetTokenInformation に失敗しました".to_string()));
    }

    let token_user = &*(buf.as_ptr() as *const TOKEN_USER);
    let sid_len = GetLengthSid(token_user.User.Sid);
    let sid_bytes =
        std::slice::from_raw_parts(token_user.User.Sid as *const u8, sid_len as usize).to_vec();
    Ok(sid_bytes)
}}
