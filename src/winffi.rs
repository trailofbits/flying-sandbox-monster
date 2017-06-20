#![allow(dead_code)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![cfg(windows)]

extern crate winapi;
extern crate kernel32;
extern crate libc;
extern crate widestring;

#[allow(unused_imports)]
use log::*;

use self::widestring::WideString;
use self::winapi::*;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::iter::once;

pub const SECURITY_DESCRIPTOR_MIN_LENGTH: usize = 64;
pub const SECURITY_DESCRIPTOR_REVISION: DWORD = 1;
pub const ACL_REVISION: DWORD = 2;
pub const SE_GROUP_ENABLED: DWORD = 4;

const PROC_THREAD_ATTRIBUTE_NUMBER: DWORD = 0x0000ffff;
const PROC_THREAD_ATTRIBUTE_THREAD: DWORD = 0x00010000;
const PROC_THREAD_ATTRIBUTE_INPUT: DWORD = 0x00020000;
const PROC_THREAD_ATTRIBUTE_ADDITIVE: DWORD = 0x00040000;

const ProcThreadAttributeSecurityCapabilities: DWORD = 9;
pub const PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES: SIZE_T =
    ((ProcThreadAttributeSecurityCapabilities & PROC_THREAD_ATTRIBUTE_NUMBER) |
     PROC_THREAD_ATTRIBUTE_INPUT) as SIZE_T;

pub const GENERIC_ALL: DWORD = 0x10000000 as DWORD;
pub const GENERIC_READ: DWORD = 0x80000000 as DWORD;
pub const GENERIC_WRITE: DWORD = 0x40000000 as DWORD;
pub const GENERIC_EXECUTE: DWORD = 0x20000000 as DWORD;

pub const HANDLE_FLAG_INHERIT: DWORD = 0x00000001 as DWORD;
pub const WSA_INVALID_EVENT: HANDLE = 0 as HANDLE;
pub const FD_ACCEPT: i32 = 8 as i32;

const FACILITY_WIN32: DWORD = 7;

pub fn HRESULT_FROM_WIN32(code: DWORD) -> HRESULT {
    if (code as HRESULT) <= 0 {
        code as HRESULT
    } else {
        ((code & 0x0000ffff) | ((FACILITY_WIN32 as DWORD) << 16) | 0x80000000) as HRESULT
    }
}

// Copied from winapi-rs since we are having issues with macro-use
macro_rules! DEF_STRUCT {
    {$(#[$attrs:meta])* nodebug struct $name:ident { $($field:ident: $ftype:ty,)+ }} => {
        #[repr(C)] $(#[$attrs])*
        pub struct $name {
            $(pub $field: $ftype,)+
        }
        impl Copy for $name {}
        impl Clone for $name { fn clone(&self) -> $name { *self } }
    };
    {$(#[$attrs:meta])* struct $name:ident { $($field:ident: $ftype:ty,)+ }} => {
        #[repr(C)] #[derive(Debug)] $(#[$attrs])*
        pub struct $name {
            $(pub $field: $ftype,)+
        }
        impl Copy for $name {}
        impl Clone for $name { fn clone(&self) -> $name { *self } }
    };
}

ENUM!{enum ACL_INFORMATION_CLASS {
    AclRevisionInformation = 1,
    AclSizeInformation,
}}

DEF_STRUCT!{struct ACE_HEADER {
    AceType: BYTE,
    AceFlags: BYTE,
    AceSize: WORD,
}}

DEF_STRUCT!{struct ACCESS_ALLOWED_ACE {
    Header: ACE_HEADER,
    Mask: ACCESS_MASK,
    SidStart: DWORD,
}}

DEF_STRUCT!{struct ACCESS_DENIED_ACE {
    Header: ACE_HEADER,
    Mask: ACCESS_MASK,
    SidStart: DWORD,
}}

DEF_STRUCT!{struct ACL_SIZE_INFORMATION {
    AceCount: DWORD,
    AclBytesInUse: DWORD,
    AclBytesFree: DWORD,
}}

DEF_STRUCT!{struct STARTUPINFOEXW {
    StartupInfo: STARTUPINFOW,
    lpAttributeList: PPROC_THREAD_ATTRIBUTE_LIST,
}}

pub type PACE_HEADER = *mut ACE_HEADER;
pub type PACCESS_ALLOWED_ACE = *mut ACCESS_ALLOWED_ACE;
pub type PACCESS_DENIED_ACE = *mut ACCESS_DENIED_ACE;
pub type PACL_SIZE_INFORMATION = *mut ACL_SIZE_INFORMATION;
pub type LPSTARTUPINFOEXW = *mut STARTUPINFOEXW;

pub struct SidPtr {
    pub raw_ptr: PSID,
}

impl SidPtr {
    pub fn new(ptr: PSID) -> SidPtr {
        SidPtr { raw_ptr: ptr }
    }
}

impl Drop for SidPtr {
    fn drop(&mut self) {
        if self.raw_ptr != (0 as PSID) {
            unsafe {
                FreeSid(self.raw_ptr);
            }
        }
    }
}

pub fn string_to_sid(StringSid: &str) -> Result<SidPtr, DWORD> {
    let mut pSid: PSID = 0 as PSID;
    let wSid: Vec<u16> = OsStr::new(StringSid)
        .encode_wide()
        .chain(once(0))
        .collect();

    if unsafe { ConvertStringSidToSidW(wSid.as_ptr(), &mut pSid) } == 0 {
        return Err(unsafe { kernel32::GetLastError() });
    }

    Ok(SidPtr::new(pSid))
}

pub fn sid_to_string(pSid: PSID) -> Result<String, DWORD> {
    let mut rawStringSid: LPWSTR = 0 as LPWSTR;

    if unsafe { ConvertSidToStringSidW(pSid, &mut rawStringSid) } == 0 ||
       rawStringSid == (0 as LPWSTR) {
        return Err(unsafe { kernel32::GetLastError() });
    }

    let rawStringSidLen = unsafe { libc::wcslen(rawStringSid) };
    let out = unsafe { WideString::from_ptr(rawStringSid, rawStringSidLen) };

    unsafe { kernel32::LocalFree(rawStringSid as HLOCAL) };

    Ok(out.to_string_lossy())
}

#[test]
fn test_invalid_sid() {
    let result = string_to_sid("INVALID_SID");
    assert!(result.is_err());

    let result2 = sid_to_string(0 as PSID);
    assert!(result2.is_err());
}

#[test]
fn test_sid_conv() {
    let orig_sid = "S-1-5-32-556";

    let result = string_to_sid(orig_sid);
    assert!(result.is_ok());

    let result2 = sid_to_string(result.unwrap().raw_ptr);
    assert!(result2.is_ok());

    assert_eq!(result2.unwrap(), orig_sid);
}

pub struct HandlePtr {
    pub raw: HANDLE,
}

impl HandlePtr {
    pub fn new(ptr: HANDLE) -> HandlePtr {
        HandlePtr { raw: ptr }
    }
}

impl Drop for HandlePtr {
    fn drop(&mut self) {
        unsafe {
            kernel32::CloseHandle(self.raw);
        }
    }
}

#[link(name = "advapi32")]
extern "system" {
    pub fn GetFileSecurityW(lpFileName: LPCWSTR,
                            RequestedInformation: SECURITY_INFORMATION,
                            pSecurityDescriptor: PSECURITY_DESCRIPTOR,
                            nLength: DWORD,
                            lpnLengthNeeded: LPDWORD)
                            -> BOOL;
    pub fn InitializeSecurityDescriptor(pSecurityDescriptor: PSECURITY_DESCRIPTOR,
                                        dwRevision: DWORD)
                                        -> BOOL;
    pub fn GetSecurityDescriptorDacl(pSecurityDescriptor: PSECURITY_DESCRIPTOR,
                                     lpbDaclPresent: LPBOOL,
                                     pDacl: *mut PACL,
                                     lpbDaclDefaulted: LPBOOL)
                                     -> BOOL;
    pub fn GetAclInformation(pAcl: PACL,
                             pAclInformation: LPVOID,
                             nAclInformationLength: DWORD,
                             dwAclInformationClass: ACL_INFORMATION_CLASS)
                             -> BOOL;
    pub fn InitializeAcl(pAcl: PACL, nAclLength: DWORD, dwAclRevision: DWORD) -> BOOL;
    pub fn GetAce(pAcl: PACL, dwAceIndex: DWORD, pAce: *mut PACE_HEADER) -> BOOL;
    pub fn ConvertSidToStringSidW(Sid: PSID, StringSid: *mut LPWSTR) -> BOOL;
    pub fn ConvertStringSidToSidW(StringSid: LPCWSTR, Sid: *mut PSID) -> BOOL;
    pub fn EqualSid(pSid1: PSID, pSid2: PSID) -> BOOL;
    pub fn AddAce(pAcl: PACL,
                  dwAcerevision: DWORD,
                  dwStartingAceIndex: DWORD,
                  pAceList: LPVOID,
                  nAceListLength: DWORD)
                  -> BOOL;
    pub fn AddAccessAllowedAce(pAcl: PACL,
                               dwAceRevision: DWORD,
                               AccessMask: DWORD,
                               pSid: PSID)
                               -> BOOL;
    pub fn AddAccessDeniedAce(pAcl: PACL,
                              dwAceRevision: DWORD,
                              AccessMask: DWORD,
                              pSid: PSID)
                              -> BOOL;
    pub fn SetSecurityDescriptorDacl(pSecurityDescriptor: PSECURITY_DESCRIPTOR,
                                     bDaclPresent: BOOL,
                                     pDacl: PACL,
                                     pDaclDefaulted: BOOL)
                                     -> BOOL;
    pub fn SetFileSecurityW(lpFileName: LPCWSTR,
                            SecurityInformation: SECURITY_INFORMATION,
                            pSecurityDescriptor: PSECURITY_DESCRIPTOR)
                            -> BOOL;
    pub fn GetLengthSid(pSid: PSID) -> DWORD;
    pub fn FreeSid(pSid: PSID) -> PVOID;
}

#[link(name = "userenv")]
extern "system" {
    pub fn CreateAppContainerProfile(pszAppContainerName: PCWSTR,
                                     pszDisplayName: PCWSTR,
                                     pszDescription: PCWSTR,
                                     pCapabilities: PSID_AND_ATTRIBUTES,
                                     dwCapabilityCount: DWORD,
                                     ppSidAppContainerSid: *mut PSID)
                                     -> HRESULT;
    pub fn DeriveAppContainerSidFromAppContainerName(pszAppContainerName: PCWSTR,
                                                     ppsidAppContainerSid: *mut PSID)
                                                     -> HRESULT;
    pub fn DeleteAppContainerProfile(pszAppContainerName: PCWSTR) -> HRESULT;
}
