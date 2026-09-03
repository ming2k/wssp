use sigil_core::{SigilError, Result};
use std::os::unix::io::AsRawFd;
use tokio::net::UnixStream;

/// Checks that the peer connected to the Unix socket belongs to the same UID.
#[cfg(target_os = "linux")]
pub fn check_peer_credentials(stream: &UnixStream) -> Result<()> {
    let fd = stream.as_raw_fd();
    let mut ucred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;

    let res = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut ucred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };

    if res != 0 {
        return Err(SigilError::AccessDenied(
            "Failed to retrieve SO_PEERCRED from socket".into(),
        ));
    }

    let my_uid = unsafe { libc::getuid() };
    if ucred.uid != my_uid {
        return Err(SigilError::AccessDenied(format!(
            "Peer UID {} does not match daemon UID {}",
            ucred.uid, my_uid
        )));
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn check_peer_credentials(_stream: &UnixStream) -> Result<()> {
    Ok(())
}
