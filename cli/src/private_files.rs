use std::{
    io,
    path::{Path, PathBuf},
};

pub fn runtime_root() -> io::Result<PathBuf> {
    #[cfg(windows)]
    return std::env::var_os("LOCALAPPDATA")
        .map(|path| PathBuf::from(path).join("burpctl"))
        .ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, "LOCALAPPDATA unavailable"));
    #[cfg(unix)]
    {
        // The same short path works for GUI and shell processes without shared environment variables.
        Ok(std::fs::canonicalize("/tmp")?.join(format!("burpctl-{}", unsafe { libc::geteuid() })))
    }
}

#[cfg(unix)]
pub fn check(path: &Path, socket: bool) -> io::Result<()> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let metadata = std::fs::symlink_metadata(path)?;
    let valid_type = if socket {
        metadata.file_type().is_socket()
    } else {
        metadata.is_dir() || (metadata.is_file() && metadata.nlink() == 1)
    };
    let mode = if metadata.is_dir() { 0o700 } else { 0o600 };
    // geteuid has no preconditions and does not acquire resources.
    if !valid_type
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o7777 != mode
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Runtime path is not private",
        ));
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::{
        fs::{PermissionsExt, symlink},
        net::UnixListener,
    };

    #[test]
    fn unix_runtime_rejects_public_modes_links_and_wrong_types() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        check(directory.path(), false).unwrap();
        let file = directory.path().join("credential");
        std::fs::write(&file, b"synthetic").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        check(&file, false).unwrap();
        assert!(check(&file, true).is_err());
        let link = directory.path().join("link");
        symlink(&file, &link).unwrap();
        assert!(check(&link, false).is_err());
        std::fs::remove_file(&link).unwrap();
        std::fs::hard_link(&file, &link).unwrap();
        assert!(check(&file, false).is_err());
        std::fs::remove_file(&link).unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(check(&file, false).is_err());
        let socket = directory.path().join("s");
        let _listener = UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        check(&socket, true).unwrap();
        assert!(check(&socket, false).is_err());
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(check(directory.path(), false).is_err());
    }
}

#[cfg(windows)]
pub fn check(path: &Path, socket: bool) -> io::Result<()> {
    use std::{
        os::windows::{ffi::OsStrExt, fs::MetadataExt},
        ptr,
    };
    use windows_sys::Win32::{
        Foundation::{CloseHandle, LocalFree},
        Security::{
            Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT},
            *,
        },
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };
    let metadata = std::fs::symlink_metadata(path)?;
    if !socket && metadata.file_attributes() & 0x400 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Reparse point rejected",
        ));
    }
    let name: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    // Win32 owns the descriptor; token storage is word-aligned and remains alive
    // until all SID comparisons complete. Every acquired handle is released.
    unsafe {
        let mut token = ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut size = 0;
        GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut size);
        if size == 0 || size > 65536 {
            CloseHandle(token);
            return Err(io::Error::last_os_error());
        }
        let mut user = vec![0usize; (size as usize).div_ceil(size_of::<usize>())];
        let got_user =
            GetTokenInformation(token, TokenUser, user.as_mut_ptr().cast(), size, &mut size);
        CloseHandle(token);
        if got_user == 0 {
            return Err(io::Error::last_os_error());
        }
        let current = (*(user.as_ptr().cast::<TOKEN_USER>())).User.Sid;
        let mut owner = ptr::null_mut();
        let mut acl = ptr::null_mut();
        let mut descriptor = ptr::null_mut();
        let status = GetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut acl,
            ptr::null_mut(),
            &mut descriptor,
        );
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        let valid = (|| {
            if owner.is_null()
                || acl.is_null()
                || EqualSid(owner, current) == 0
                || (*acl).AceCount == 0
            {
                return false;
            }
            for index in 0..(*acl).AceCount {
                let mut ace = ptr::null_mut();
                if GetAce(acl, index as u32, &mut ace) == 0 {
                    return false;
                }
                let header = &*ace.cast::<ACE_HEADER>();
                // ACCESS_ALLOWED_ACE_TYPE = 0; reject every other ACL form.
                if header.AceType != 0
                    || (header.AceSize as usize) < size_of::<ACCESS_ALLOWED_ACE>()
                {
                    return false;
                }
                let sid = ptr::addr_of!((*ace.cast::<ACCESS_ALLOWED_ACE>()).SidStart)
                    .cast_mut()
                    .cast();
                if IsValidSid(sid) == 0 || EqualSid(sid, current) == 0 {
                    return false;
                }
            }
            true
        })();
        LocalFree(descriptor);
        if valid {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Runtime ACL is not private",
            ))
        }
    }
}
