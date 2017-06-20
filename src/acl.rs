#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![cfg(windows)]

extern crate winapi;
extern crate kernel32;
extern crate field_offset;
extern crate libc;

#[allow(unused_imports)]
use log::*;

#[cfg(test)]
extern crate tempdir;

use super::winffi;

use super::winffi::{SECURITY_DESCRIPTOR_REVISION, PACE_HEADER, ACCESS_ALLOWED_ACE,
                    ACCESS_DENIED_ACE, SECURITY_DESCRIPTOR_MIN_LENGTH, ACL_REVISION,
                    string_to_sid, sid_to_string};
use self::winapi::{PSECURITY_DESCRIPTOR, PACL, DACL_SECURITY_INFORMATION, PSID, ACL, DWORD,
                   LPVOID, BOOL};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;
use std::iter::once;
use std::mem;

#[cfg(test)]
use super::winffi::{GENERIC_ALL, GENERIC_READ, GENERIC_WRITE};

#[cfg(test)]
use std::fs::File;

#[cfg(test)]
use self::tempdir::TempDir;

#[cfg(test)]
use std::io::prelude::*;

#[allow(unused_imports)]
use self::field_offset::*;

pub type ACL_ENTRY_TYPE = u8;

pub const ACCESS_ALLOWED: u8 = 0;
#[allow(dead_code)]
pub const ACCESS_DENIED: u8 = 1;

#[allow(dead_code)]
pub struct AccessControlEntry {
    pub entryType: u8,
    pub flags: u8,
    pub mask: u32,
    pub sid: String,
}

#[allow(dead_code)]
fn get_dacl(path: &str) -> Result<(Vec<u8>, PACL), DWORD> {
    let wPath: Vec<u16> = OsStr::new(path).encode_wide().chain(once(0)).collect();
    let mut bufSize: DWORD = 0;
    let mut status = unsafe {
        winffi::GetFileSecurityW(wPath.as_ptr(),
                                 DACL_SECURITY_INFORMATION,
                                 null_mut(),
                                 0,
                                 &mut bufSize)
    };
    if status != 0 {
        return Err(unsafe { kernel32::GetLastError() });
    }

    let mut securityDesc: Vec<u8> = Vec::with_capacity(bufSize as usize);
    status = unsafe {
        winffi::GetFileSecurityW(wPath.as_ptr(),
                                 DACL_SECURITY_INFORMATION,
                                 securityDesc.as_mut_ptr() as LPVOID,
                                 bufSize,
                                 &mut bufSize)
    };

    if status == 0 {
        return Err(unsafe { kernel32::GetLastError() });
    }

    let mut pDacl: PACL = 0 as PACL;
    let mut daclPresent: BOOL = 0;
    let mut daclDefault: BOOL = 0;

    let status = unsafe {
        winffi::GetSecurityDescriptorDacl(securityDesc.as_ptr() as PSECURITY_DESCRIPTOR,
                                          &mut daclPresent,
                                          &mut pDacl,
                                          &mut daclDefault)
    };

    if status == 0 || daclPresent == 0 {
        return Err(unsafe { kernel32::GetLastError() });
    }

    Ok((securityDesc, pDacl))
}

macro_rules! add_entry {
    ($z: ident, $x: ident => $y: path) => {
        {
            let entry: *mut $y = $x as *mut $y;
            let pSid = offset_of!($y => SidStart);
            $z.push(AccessControlEntry {
                entryType: unsafe { (*$x).AceType },
                flags: unsafe { (*$x).AceFlags },
                mask: unsafe { (*entry).Mask },
                sid: sid_to_string(pSid.apply_ptr_mut(entry) as PSID)?,
            })
        }
    };
}

#[allow(dead_code)]
pub struct SimpleDacl {
    entries: Vec<AccessControlEntry>,
}

#[allow(dead_code)]
impl SimpleDacl {
    pub fn new() -> SimpleDacl {
        SimpleDacl { entries: Vec::new() }
    }

    pub fn from_path(path: &str) -> Result<SimpleDacl, DWORD> {
        #[allow(unused_variables)]
        let (securityDesc, pDacl) = get_dacl(path)?;

        let mut hdr: PACE_HEADER = 0 as PACE_HEADER;
        let mut entries: Vec<AccessControlEntry> = Vec::new();

        for i in 0..unsafe { (*pDacl).AceCount } {
            if unsafe { winffi::GetAce(pDacl, i as u32, &mut hdr) } == 0 {
                return Err(unsafe { kernel32::GetLastError() });
            }

            match unsafe { (*hdr).AceType } {
                0 => add_entry!(entries, hdr => ACCESS_ALLOWED_ACE),
                1 => add_entry!(entries, hdr => ACCESS_DENIED_ACE),
                _ => return Err(0xffffffff),
            }
        }

        Ok(SimpleDacl { entries: entries })
    }

    pub fn get_entries(&self) -> &Vec<AccessControlEntry> {
        &self.entries
    }

    pub fn add_entry(&mut self, entry: AccessControlEntry) -> bool {
        let target: usize;
        match entry.entryType {
            ACCESS_ALLOWED => {
                // We are assuming that the list is proper: that denied ACEs are placed
                // prior to allow ACEs
                match self.entries.iter().position(|&ref x| x.entryType != 1) {
                    Some(x) => {
                        target = x;
                    }
                    None => {
                        target = 0xffffffff;
                    }
                }
            }
            ACCESS_DENIED => {
                target = 0;
            }
            _ => return false,
        }

        match string_to_sid(&entry.sid) {
            Err(_) => return false,
            Ok(_) => {}
        }

        if self.entries
               .iter()
               .any(|x| x.sid == entry.sid && x.entryType == entry.entryType) {
            return false;
        }

        if target == 0xffffffff {
            self.entries.push(entry)
        } else {
            self.entries.insert(target, entry)
        }

        true
    }

    pub fn entry_exists(&self, sid: &str, entryType: ACL_ENTRY_TYPE) -> Option<usize> {
        let index = match self.entries
                  .iter()
                  .position(|x| x.sid == sid && x.entryType == entryType) {
            Some(x) => x,
            _ => return None,
        };

        Some(index)
    }

    pub fn remove_entry(&mut self, sid: &str, entryType: ACL_ENTRY_TYPE) -> bool {
        if let Some(index) = self.entry_exists(sid, entryType) {
            self.entries.remove(index);
            return true;
        }

        false
    }

    pub fn apply_to_path(&self, path: &str) -> Result<usize, DWORD> {
        let wPath: Vec<u16> = OsStr::new(path).encode_wide().chain(once(0)).collect();
        let mut securityDesc: Vec<u8> = Vec::with_capacity(SECURITY_DESCRIPTOR_MIN_LENGTH);

        if unsafe {
               winffi::InitializeSecurityDescriptor(securityDesc.as_mut_ptr() as LPVOID,
                                                    SECURITY_DESCRIPTOR_REVISION)
           } == 0 {
            return Err(unsafe { kernel32::GetLastError() });
        }

        let mut aclSize = mem::size_of::<ACL>();
        for entry in &self.entries {
            let sid = string_to_sid(&entry.sid)?;
            aclSize += unsafe { winffi::GetLengthSid(sid.raw_ptr) } as usize;

            match entry.entryType {
                0 => aclSize += mem::size_of::<ACCESS_ALLOWED_ACE>() - mem::size_of::<DWORD>(),
                1 => aclSize += mem::size_of::<ACCESS_DENIED_ACE>() - mem::size_of::<DWORD>(),
                _ => return Err(0xffffffff),
            }
        }

        let mut aclBuffer: Vec<u8> = Vec::with_capacity(aclSize);
        if unsafe {
               winffi::InitializeAcl(aclBuffer.as_mut_ptr() as PACL,
                                     aclSize as DWORD,
                                     ACL_REVISION)
           } == 0 {
            return Err(unsafe { kernel32::GetLastError() });
        }

        for entry in &self.entries {
            let sid = string_to_sid(&entry.sid)?;

            match entry.entryType {
                0 => {
                    if unsafe {
                           winffi::AddAccessAllowedAce(aclBuffer.as_mut_ptr() as PACL,
                                                       ACL_REVISION,
                                                       entry.mask,
                                                       sid.raw_ptr)
                       } == 0 {
                        return Err(unsafe { kernel32::GetLastError() });
                    }
                }
                1 => {
                    if unsafe {
                           winffi::AddAccessDeniedAce(aclBuffer.as_mut_ptr() as PACL,
                                                      ACL_REVISION,
                                                      entry.mask,
                                                      sid.raw_ptr)
                       } == 0 {
                        return Err(unsafe { kernel32::GetLastError() });
                    }
                }
                _ => return Err(0xffffffff),
            }
        }

        if unsafe {
               winffi::SetSecurityDescriptorDacl(securityDesc.as_mut_ptr() as PSECURITY_DESCRIPTOR,
                                                 1,
                                                 aclBuffer.as_ptr() as PACL,
                                                 0)
           } == 0 {
            return Err(unsafe { kernel32::GetLastError() });
        }

        if unsafe {
               winffi::SetFileSecurityW(wPath.as_ptr(),
                                        DACL_SECURITY_INFORMATION,
                                        securityDesc.as_ptr() as PSECURITY_DESCRIPTOR)
           } == 0 {
            return Err(unsafe { kernel32::GetLastError() });
        }

        Ok(0)
    }
}

// ----- UNIT TESTS -----
#[test]
fn test_add_remove_entry() {
    let mut acl = SimpleDacl::new();

    // Bad sid
    assert!(!acl.add_entry(AccessControlEntry {
                               sid: String::from("FAKESID"),
                               mask: GENERIC_READ,
                               entryType: ACCESS_ALLOWED,
                               flags: 0,
                           }));
    assert_eq!(acl.get_entries().iter().count(), 0);

    // Bad entry type
    assert!(!acl.add_entry(AccessControlEntry {
                               sid: String::from("S-1-1-0"),
                               mask: GENERIC_READ,
                               entryType: 5,
                               flags: 0,
                           }));
    assert_eq!(acl.get_entries().iter().count(), 0);
    assert!(acl.entry_exists(&String::from("S-1-1-0"), 5).is_none());

    assert!(acl.add_entry(AccessControlEntry {
                              sid: String::from("S-1-1-1"),
                              mask: GENERIC_WRITE,
                              entryType: ACCESS_DENIED,
                              flags: 0,
                          }));
    assert_eq!(acl.get_entries().iter().count(), 1);
    assert!(acl.entry_exists(&String::from("S-1-1-1"), ACCESS_DENIED)
                .is_some());

    // Duplicate SID entry added
    assert!(!acl.add_entry(AccessControlEntry {
                               sid: String::from("S-1-1-1"),
                               mask: GENERIC_WRITE,
                               entryType: ACCESS_DENIED,
                               flags: 0,
                           }));
    assert_eq!(acl.get_entries().iter().count(), 1);

    assert!(acl.add_entry(AccessControlEntry {
                              sid: String::from("S-1-1-2"),
                              mask: GENERIC_READ,
                              entryType: ACCESS_ALLOWED,
                              flags: 0,
                          }));
    assert_eq!(acl.get_entries().iter().count(), 2);

    {
        let result = acl.get_entries().iter().nth(0);
        assert!(!result.is_none());

        let entry = result.unwrap();
        assert_eq!(&entry.sid, "S-1-1-1");
        assert_eq!(entry.mask, GENERIC_WRITE);
        assert_eq!(entry.entryType, ACCESS_DENIED);
    }

    {
        let result = acl.get_entries().iter().nth(1);
        assert!(!result.is_none());

        let entry = result.unwrap();
        assert_eq!(&entry.sid, "S-1-1-2");
        assert_eq!(entry.mask, GENERIC_READ);
        assert_eq!(entry.entryType, ACCESS_ALLOWED);
    }

    assert!(!acl.remove_entry("S-1-1-1", ACCESS_ALLOWED));
    assert!(acl.remove_entry("S-1-1-1", ACCESS_DENIED));
    assert_eq!(acl.get_entries().iter().count(), 1);

    {
        let result = acl.get_entries().iter().nth(0);
        assert!(!result.is_none());

        let entry = result.unwrap();
        assert_eq!(&entry.sid, "S-1-1-2");
        assert_eq!(entry.mask, GENERIC_READ);
        assert_eq!(entry.entryType, ACCESS_ALLOWED);
    }

}

#[test]
fn test_add_and_remove_acl_entry() {
    let dir_result = TempDir::new("appjail_unittest");
    assert!(dir_result.is_ok());

    let tmp_dir = dir_result.unwrap();
    let tmp_file = tmp_dir.path().join("test.txt");
    let tmp_file_path = tmp_file.to_str().unwrap();

    let file_result = File::create(tmp_file_path);
    assert!(file_result.is_ok());
    let mut fp = file_result.unwrap();
    {
        assert!(fp.write_all(b"This is a test document").is_ok());
    }

    let orig_count;
    let orig_sid;
    let orig_type;

    // Ensure initial ACL read can occur and reports somewhat correct values
    {
        let mut acl = match SimpleDacl::from_path(tmp_file_path) {
            Ok(x) => x,
            _ => {
                assert!(false);
                return;
            }
        };
        orig_count = acl.get_entries().iter().count();
        assert!(orig_count > 1);

        {
            let entry = match acl.get_entries().iter().nth(0) {
                Some(x) => x,
                _ => {
                    assert!(false);
                    return;
                }
            };
            orig_sid = entry.sid.clone();
            orig_type = entry.entryType;
        }

        assert!(acl.remove_entry(&orig_sid, orig_type));
        assert!(acl.get_entries().iter().count() != orig_count);
        assert_eq!(acl.apply_to_path(tmp_file_path), Ok(0));
    }

    // After removing an arbitrary ACL entry by SID, the removed entry should not appear
    {
        let acl = match SimpleDacl::from_path(tmp_file_path) {
            Ok(x) => x,
            _ => {
                assert!(false);
                return;
            }
        };
        assert!(acl.get_entries().iter().count() < orig_count);
        assert!(!acl.get_entries().iter().any(|ref x| x.sid == orig_sid));
    }

    // Wipe out ACL with new one and read ACL back
    {
        let mut acl = SimpleDacl::new();
        assert!(acl.add_entry(AccessControlEntry {
                                  sid: String::from("S-1-1-0"),
                                  mask: GENERIC_ALL,
                                  entryType: ACCESS_ALLOWED,
                                  flags: 0,
                              }));
        assert_eq!(acl.apply_to_path(tmp_file_path), Ok(0));

        acl = match SimpleDacl::from_path(tmp_file_path) {
            Ok(x) => x,
            _ => {
                assert!(false);
                return;
            }
        };

        assert_eq!(acl.get_entries().iter().count(), 1);

        let entry = match acl.get_entries().iter().nth(0) {
            Some(x) => x,
            _ => {
                assert!(false);
                return;
            }
        };

        assert_eq!(entry.sid, "S-1-1-0");
        assert_eq!(entry.mask, 0x001f01ff);
        assert_eq!(entry.entryType, ACCESS_ALLOWED);
    }
}
