use pamsm::{pam_module, Pam, PamError, PamFlag, PamLibExt, PamServiceModule};
use std::ffi::CString;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;

struct WssPam;

impl PamServiceModule for WssPam {
    fn open_session(_pamh: Pam, _flags: PamFlag, _args: Vec<String>) -> PamError {
        PamError::SUCCESS
    }

    fn authenticate(pamh: Pam, _flags: PamFlag, _args: Vec<String>) -> PamError {
        let user = match pamh.get_cached_user() {
            Ok(Some(u)) => u.to_string_lossy().into_owned(),
            _ => return PamError::USER_UNKNOWN,
        };

        let authtok = match pamh.get_cached_authtok() {
            Ok(Some(tok)) => tok.to_string_lossy().into_owned(),
            _ => return PamError::SUCCESS,
        };

        if authtok.is_empty() {
            return PamError::SUCCESS;
        }

        let c_user = match CString::new(user) {
            Ok(c) => c,
            Err(_) => return PamError::USER_UNKNOWN,
        };

        let passwd = unsafe { libc::getpwnam(c_user.as_ptr()) };
        if passwd.is_null() {
            return PamError::USER_UNKNOWN;
        }

        let uid = unsafe { (*passwd).pw_uid };
        let gid = unsafe { (*passwd).pw_gid };

        let path_str = format!("/run/user/{}/wssp-pam-token", uid);

        let mut file = match OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path_str)
        {
            Ok(f) => f,
            Err(_) => return PamError::SESSION_ERR,
        };

        if file.write_all(authtok.as_bytes()).is_err() {
            return PamError::SESSION_ERR;
        }

        let c_path = match CString::new(path_str) {
            Ok(c) => c,
            Err(_) => return PamError::SESSION_ERR,
        };

        if unsafe { libc::chown(c_path.as_ptr(), uid, gid) } != 0 {
            return PamError::SESSION_ERR;
        }

        PamError::SUCCESS
    }

    fn setcred(_pam: Pam, _flags: PamFlag, _args: Vec<String>) -> PamError {
        PamError::SUCCESS
    }

    fn close_session(_pam: Pam, _flags: PamFlag, _args: Vec<String>) -> PamError {
        PamError::SUCCESS
    }
}

pam_module!(WssPam);
