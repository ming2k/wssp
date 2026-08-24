use pamsm::{pam_module, Pam, PamError, PamFlag, PamLibExt, PamServiceModule};
use std::ffi::CString;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;

struct WssPam;

fn write_pam_token(pamh: &Pam) -> PamError {
    let user = match pamh.get_cached_user() {
        Ok(Some(u)) => u.to_string_lossy().into_owned(),
        _ => return PamError::SUCCESS,
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
        Err(_) => return PamError::SUCCESS,
    };

    let passwd = unsafe { libc::getpwnam(c_user.as_ptr()) };
    if passwd.is_null() {
        return PamError::SUCCESS;
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
        Err(_) => return PamError::SUCCESS,
    };

    if file.write_all(authtok.as_bytes()).is_err() {
        return PamError::SUCCESS;
    }
    let _ = file.flush();

    let c_path = match CString::new(path_str) {
        Ok(c) => c,
        Err(_) => return PamError::SUCCESS,
    };

    unsafe { libc::chown(c_path.as_ptr(), uid, gid) };

    PamError::SUCCESS
}

impl PamServiceModule for WssPam {
    fn authenticate(pamh: Pam, _flags: PamFlag, _args: Vec<String>) -> PamError {
        // Authenticate hook: only verify user exists.
        // Token planting is deferred to setcred / open_session when authentication is fully committed.
        if pamh.get_cached_user().is_err() {
            return PamError::USER_UNKNOWN;
        }
        PamError::SUCCESS
    }

    fn setcred(pamh: Pam, flags: PamFlag, _args: Vec<String>) -> PamError {
        match flags {
            PamFlag::DELETE_CRED => {}
            _ => {
                write_pam_token(&pamh);
            }
        }
        PamError::SUCCESS
    }

    fn open_session(pamh: Pam, _flags: PamFlag, _args: Vec<String>) -> PamError {
        // Fallback planting in case caller commits via session open instead of setcred
        write_pam_token(&pamh);
        PamError::SUCCESS
    }

    fn close_session(_pamh: Pam, _flags: PamFlag, _args: Vec<String>) -> PamError {
        PamError::SUCCESS
    }
}

pam_module!(WssPam);
