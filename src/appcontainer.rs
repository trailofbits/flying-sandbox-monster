#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![cfg(windows)]

extern crate winapi;
extern crate kernel32;
extern crate field_offset;
extern crate libc;
extern crate widestring;
extern crate log;

#[allow(unused_imports)]
use log::*;
use super::winffi;

use super::winffi::{HRESULT_FROM_WIN32, SE_GROUP_ENABLED, string_to_sid, sid_to_string,
                    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, STARTUPINFOEXW, LPSTARTUPINFOEXW,
                    HandlePtr, HANDLE_FLAG_INHERIT};
use self::winapi::{DWORD, LPVOID, LPWSTR, PSID, INVALID_HANDLE_VALUE, PSID_AND_ATTRIBUTES,
                   SID_AND_ATTRIBUTES, ERROR_SUCCESS, ERROR_ALREADY_EXISTS, HRESULT,
                   SECURITY_CAPABILITIES, LPPROC_THREAD_ATTRIBUTE_LIST,
                   PPROC_THREAD_ATTRIBUTE_LIST, SIZE_T, PSIZE_T, PVOID, PSECURITY_CAPABILITIES,
                   STARTUPINFOW, LPSTARTUPINFOW, HANDLE, WORD, LPBYTE, STARTF_USESTDHANDLES,
                   STARTF_USESHOWWINDOW, SW_HIDE, ERROR_FILE_NOT_FOUND, PROCESS_INFORMATION,
                   EXTENDED_STARTUPINFO_PRESENT, LPSECURITY_ATTRIBUTES};
use std::path::Path;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::iter::once;
use std::mem;

#[cfg(test)]
use std::env;

#[cfg(test)]
use std::path::PathBuf;

#[cfg(test)]
use self::winapi::{INFINITE, WAIT_OBJECT_0};

#[allow(dead_code)]
pub struct Profile {
    pub profile: String,
    childPath: String,
    outboundNetwork: bool,
    debug: bool,
    pub sid: String,
}

#[allow(dead_code)]
impl Profile {
    pub fn new(profile: &str, path: &str) -> Result<Profile, HRESULT> {
        let mut pSid: PSID = 0 as PSID;
        let profile_name: Vec<u16> = OsStr::new(profile)
            .encode_wide()
            .chain(once(0))
            .collect();

        let path_obj = Path::new(path);
        if !path_obj.exists() || !path_obj.is_file() {
            return Err(HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND));
        }

        let mut hr = unsafe {
            winffi::CreateAppContainerProfile(profile_name.as_ptr(),
                                              profile_name.as_ptr(),
                                              profile_name.as_ptr(),
                                              0 as PSID_AND_ATTRIBUTES,
                                              0 as DWORD,
                                              &mut pSid)
        };

        if hr == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS) {
            hr = unsafe {
                winffi::DeriveAppContainerSidFromAppContainerName(profile_name.as_ptr(), &mut pSid)
            };
            if hr != (ERROR_SUCCESS as HRESULT) {
                return Err(hr);
            }
        }

        let string_sid = match sid_to_string(pSid) {
            Ok(x) => x,
            Err(x) => return Err(x as HRESULT),
        };

        unsafe { winffi::FreeSid(pSid) };

        Ok(Profile {
               profile: profile.to_string(),
               childPath: path.to_string(),
               outboundNetwork: true,
               debug: false,
               sid: string_sid,
           })
    }

    pub fn remove(profile: &str) -> bool {
        let profile_name: Vec<u16> = OsStr::new(profile)
            .encode_wide()
            .chain(once(0))
            .collect();
        let mut pSid: PSID = 0 as PSID;

        let mut hr = unsafe {
            winffi::DeriveAppContainerSidFromAppContainerName(profile_name.as_ptr(), &mut pSid)
        };

        if hr == (ERROR_SUCCESS as HRESULT) {
            hr = unsafe { winffi::DeleteAppContainerProfile(profile_name.as_ptr()) };
            return hr == (ERROR_SUCCESS as HRESULT);
        }

        false
    }

    pub fn enable_outbound_network(&mut self, has_outbound_network: bool) {
        self.outboundNetwork = has_outbound_network;
    }

    pub fn enable_debug(&mut self, is_debug: bool) {
        self.debug = is_debug;
    }

    pub fn launch(&self, stdin: HANDLE, stdout: HANDLE, dirPath: &str) -> Result<HandlePtr, DWORD> {
        let network_allow_sid = match string_to_sid("S-1-15-3-1") {
            Ok(x) => x,
            Err(_) => return Err(0xffffffff),
        };
        let sid = string_to_sid(&self.sid)?;
        let mut capabilities = SECURITY_CAPABILITIES {
            AppContainerSid: sid.raw_ptr,
            Capabilities: 0 as PSID_AND_ATTRIBUTES,
            CapabilityCount: 0,
            Reserved: 0,
        };
        let mut attrs;
        let mut si = STARTUPINFOEXW {
            StartupInfo: STARTUPINFOW {
                cb: 0 as DWORD,
                lpReserved: 0 as LPWSTR,
                lpDesktop: 0 as LPWSTR,
                lpTitle: 0 as LPWSTR,
                dwX: 0 as DWORD,
                dwY: 0 as DWORD,
                dwXSize: 0 as DWORD,
                dwYSize: 0 as DWORD,
                dwXCountChars: 0 as DWORD,
                dwYCountChars: 0 as DWORD,
                dwFillAttribute: 0 as DWORD,
                dwFlags: 0 as DWORD,
                wShowWindow: 0 as WORD,
                cbReserved2: 0 as WORD,
                lpReserved2: 0 as LPBYTE,
                hStdInput: 0 as HANDLE,
                hStdOutput: 0 as HANDLE,
                hStdError: 0 as HANDLE,
            },
            lpAttributeList: 0 as PPROC_THREAD_ATTRIBUTE_LIST,
        };
        let mut dwCreationFlags: DWORD = 4 as DWORD;
        let mut attrBuf: Vec<u8>;

        if !self.debug {
            debug!("Setting up AppContainer");

            if self.outboundNetwork {
                debug!("Setting up SID_AND_ATTRIBUTES for outbound network permissions");

                attrs = SID_AND_ATTRIBUTES {
                    Sid: network_allow_sid.raw_ptr,
                    Attributes: SE_GROUP_ENABLED,
                };

                capabilities.CapabilityCount = 1;
                capabilities.Capabilities = &mut attrs;
            }

            let mut listSize: SIZE_T = 0;
            if unsafe {
                   kernel32::InitializeProcThreadAttributeList(0 as LPPROC_THREAD_ATTRIBUTE_LIST,
                                                               1,
                                                               0,
                                                               &mut listSize)
               } !=
               0 {
                debug!("InitializeProcThreadAttributeList failed: GLE={:}",
                       unsafe { kernel32::GetLastError() });
                return Err(unsafe { kernel32::GetLastError() });
            }

            attrBuf = Vec::with_capacity(listSize as usize);
            if unsafe {
                   kernel32::InitializeProcThreadAttributeList(attrBuf.as_mut_ptr() as
                                                               LPPROC_THREAD_ATTRIBUTE_LIST,
                                                               1,
                                                               0,
                                                               &mut listSize)
               } ==
               0 {
                debug!("InitializeProcThreadAttributeList failed: GLE={:}",
                       unsafe { kernel32::GetLastError() });
                return Err(unsafe { kernel32::GetLastError() });
            }

            if unsafe {
                kernel32::UpdateProcThreadAttribute(attrBuf.as_mut_ptr() as LPPROC_THREAD_ATTRIBUTE_LIST, 
                                                    0, 
                                                    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, 
                                                    mem::transmute::<PSECURITY_CAPABILITIES, LPVOID>(&mut capabilities), 
                                                    mem::size_of::<SECURITY_CAPABILITIES>() as SIZE_T, 
                                                    0 as PVOID, 
                                                    0 as PSIZE_T) } == 0 {
                debug!("UpdateProcThreadAttribute failed: GLE={:}", unsafe { kernel32::GetLastError() });
                return Err(unsafe { kernel32::GetLastError() })
            }

            si.StartupInfo.cb = mem::size_of::<STARTUPINFOEXW>() as DWORD;
            si.lpAttributeList = attrBuf.as_mut_ptr() as PPROC_THREAD_ATTRIBUTE_LIST;

            dwCreationFlags |= EXTENDED_STARTUPINFO_PRESENT;
        } else {
            debug!("Debug mode -- no extended STARTUPINFO");
            si.StartupInfo.cb = mem::size_of::<STARTUPINFOW>() as DWORD;
        }

        si.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;

        if stdout != INVALID_HANDLE_VALUE && stdin != INVALID_HANDLE_VALUE {
            si.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
            si.StartupInfo.hStdInput = stdin as HANDLE;
            si.StartupInfo.hStdOutput = stdout as HANDLE;
            si.StartupInfo.hStdError = stdout as HANDLE;

            // Ensure the handle is inheritable
            if unsafe { kernel32::SetHandleInformation(stdin, HANDLE_FLAG_INHERIT, 1) } == 0 {
                return Err(unsafe { kernel32::GetLastError() });
            }

            if stdin != stdout {
                if unsafe { kernel32::SetHandleInformation(stdout, HANDLE_FLAG_INHERIT, 1) } == 0 {
                    return Err(unsafe { kernel32::GetLastError() });
                }
            }
        }

        si.StartupInfo.wShowWindow = SW_HIDE as WORD;

        let currentDir: Vec<u16> = OsStr::new(dirPath)
            .encode_wide()
            .chain(once(0))
            .collect();
        let cmdLine: Vec<u16> = OsStr::new(&self.childPath)
            .encode_wide()
            .chain(once(0))
            .collect();
        let mut pi = PROCESS_INFORMATION {
            hProcess: 0 as HANDLE,
            hThread: 0 as HANDLE,
            dwProcessId: 0 as DWORD,
            dwThreadId: 0 as DWORD,
        };

        if unsafe {
               kernel32::CreateProcessW(cmdLine.as_ptr(),
                                        0 as LPWSTR,
                                        0 as LPSECURITY_ATTRIBUTES,
                                        0 as LPSECURITY_ATTRIBUTES,
                                        1,
                                        dwCreationFlags,
                                        0 as LPVOID,
                                        currentDir.as_ptr(),
                                        mem::transmute::<LPSTARTUPINFOEXW, LPSTARTUPINFOW>(&mut si),
                                        &mut pi)
           } == 0 {
            println!("CreateProcess failed: GLE={:}",
                     unsafe { kernel32::GetLastError() });
            return Err(unsafe { kernel32::GetLastError() });
        }

        debug!("  Child PID = {:}", pi.dwProcessId);

        unsafe { kernel32::CloseHandle(pi.hThread) };

        Ok(HandlePtr::new(pi.hProcess))
    }
}

// ----- UNIT TESTS -----
#[test]
fn test_profile_sid() {
    {
        let result = Profile::new("default_profile", "INVALID_FILE");
        assert!(result.is_err());
    }

    {
        let mut result = Profile::new("cmd_profile", "\\Windows\\System32\\cmd.exe");
        assert!(result.is_ok());

        let profile = result.unwrap();

        result = Profile::new("cmd_profile", "\\Windows\\System32\\cmd.exe");
        assert!(result.is_ok());

        let same_profile = result.unwrap();
        assert_eq!(profile.sid, same_profile.sid);

        assert!(Profile::remove("cmd_profile"));

        result = Profile::new("cmd_profile1", "\\Windows\\System32\\cmd.exe");
        assert!(result.is_ok());

        let new_profile = result.unwrap();
        assert!(profile.sid != new_profile.sid);
    }
}

#[cfg(test)]
fn get_unittest_support_path() -> Option<PathBuf> {
    let mut dir_path = match env::current_exe() {
        Ok(x) => x,
        Err(_) => return None,
    };

    while dir_path.pop() {
        dir_path.push("unittest_support");
        if dir_path.exists() && dir_path.is_dir() {
            return Some(dir_path);
        }
        dir_path.pop();
    }

    None
}

#[cfg(test)]
struct ProfileWrapper {
    name: String,
}

#[cfg(test)]
impl Drop for ProfileWrapper {
    fn drop(&mut self) {
        Profile::remove(&self.name);
    }
}

#[cfg(test)]
const OUTBOUND_CONNECT_MASK: u32 = 0x00000001;
#[cfg(test)]
const FILE_READ_MASK: u32 = 0x00000002;
#[cfg(test)]
const FILE_WRITE_MASK: u32 = 0x00000004;
#[cfg(test)]
const REGISTRY_READ_MASK: u32 = 0x00000008;
#[cfg(test)]
const REGISTRY_WRITE_MASK: u32 = 0x00000010;

#[allow(unused_variables)]
#[test]
fn test_appcontainer() {
    let result = get_unittest_support_path();
    assert!(!result.is_none());

    let profile_name = String::from("test_default_appjail");

    let mut child_path = result.unwrap();
    let dir_path = child_path.clone();
    child_path.push("sandbox-test.exe");

    println!("dir_path = {:?}", dir_path);
    println!("Attempting to create AppContainer profile...");

    if let Ok(mut profile) = Profile::new(&profile_name, child_path.to_str().unwrap()) {
        let wrapper = ProfileWrapper { name: profile_name };

        {
            println!("Testing with default privileges");
            let launch_result = profile.launch(INVALID_HANDLE_VALUE,
                                               INVALID_HANDLE_VALUE,
                                               dir_path.to_str().unwrap());
            assert!(launch_result.is_ok());

            let hProcess = launch_result.unwrap();
            assert_eq!(unsafe { kernel32::WaitForSingleObject(hProcess.raw, INFINITE) },
                       WAIT_OBJECT_0);

            let mut dwExitCode: DWORD = 0 as DWORD;
            assert!(unsafe { kernel32::GetExitCodeProcess(hProcess.raw, &mut dwExitCode) } != 0);

            assert!((dwExitCode & OUTBOUND_CONNECT_MASK) == 0);
            assert!((dwExitCode & FILE_READ_MASK) != 0);
            assert!((dwExitCode & FILE_WRITE_MASK) != 0);
            assert!((dwExitCode & REGISTRY_READ_MASK) == 0);
            assert!((dwExitCode & REGISTRY_WRITE_MASK) != 0);
        }

        println!("Disabling outbound network connections");
        profile.enable_outbound_network(false);

        {
            println!("Testing without outbound network connections");
            let launch_result = profile.launch(INVALID_HANDLE_VALUE,
                                               INVALID_HANDLE_VALUE,
                                               dir_path.to_str().unwrap());
            assert!(launch_result.is_ok());

            let hProcess = launch_result.unwrap();
            assert_eq!(unsafe { kernel32::WaitForSingleObject(hProcess.raw, INFINITE) },
                       WAIT_OBJECT_0);

            let mut dwExitCode: DWORD = 0 as DWORD;
            assert!(unsafe { kernel32::GetExitCodeProcess(hProcess.raw, &mut dwExitCode) } != 0);

            assert!((dwExitCode & OUTBOUND_CONNECT_MASK) != 0);
            assert!((dwExitCode & FILE_READ_MASK) != 0);
            assert!((dwExitCode & FILE_WRITE_MASK) != 0);
            assert!((dwExitCode & REGISTRY_READ_MASK) == 0);
            assert!((dwExitCode & REGISTRY_WRITE_MASK) != 0);
        }

        println!("Enabling outbound network connections");
        profile.enable_outbound_network(true);

        println!("Disabling AppContainer");
        profile.enable_debug(true);

        {
            println!("Testing debug mode");
            let launch_result = profile.launch(INVALID_HANDLE_VALUE,
                                               INVALID_HANDLE_VALUE,
                                               dir_path.to_str().unwrap());
            assert!(launch_result.is_ok());

            let hProcess = launch_result.unwrap();
            assert_eq!(unsafe { kernel32::WaitForSingleObject(hProcess.raw, INFINITE) },
                       WAIT_OBJECT_0);

            let mut dwExitCode: DWORD = 0 as DWORD;
            assert!(unsafe { kernel32::GetExitCodeProcess(hProcess.raw, &mut dwExitCode) } != 0);

            assert!((dwExitCode & OUTBOUND_CONNECT_MASK) == 0);
            assert!((dwExitCode & FILE_READ_MASK) == 0);
            assert!((dwExitCode & FILE_WRITE_MASK) == 0);
            assert!((dwExitCode & REGISTRY_READ_MASK) == 0);
            assert!((dwExitCode & REGISTRY_WRITE_MASK) == 0);
        }
    } else {
        println!("Failed to create AppContainer profile");
        assert!(false);
    }
}

#[allow(unused_variables)]
#[test]
fn test_stdout_redirect() {
    let result = get_unittest_support_path();
    assert!(!result.is_none());

    let profile_name = String::from("test_default_appjail2");

    let mut child_path = result.unwrap();
    let dir_path = child_path.clone();
    child_path.push("greenhornd.exe");

    let raw_profile = Profile::new(&profile_name, child_path.to_str().unwrap());
    if let Err(x) = raw_profile {
        println!("GLE={:}", x);
    }
    assert!(raw_profile.is_ok());

    let wrapper = ProfileWrapper { name: profile_name };
    let profile = raw_profile.unwrap();

    let mut rChildStdin: HANDLE = 0 as HANDLE;
    let mut wChildStdin: HANDLE = 0 as HANDLE;
    let mut rChildStdout: HANDLE = 0 as HANDLE;
    let mut wChildStdout: HANDLE = 0 as HANDLE;

    let mut saAttr = winapi::SECURITY_ATTRIBUTES {
        nLength: mem::size_of::<winapi::SECURITY_ATTRIBUTES>() as DWORD,
        lpSecurityDescriptor: 0 as LPVOID,
        bInheritHandle: 0,
    };

    println!("Creating stdin/stdout anonymous pipes");
    assert!(unsafe {
                kernel32::CreatePipe(&mut rChildStdout, &mut wChildStdout, &mut saAttr, 0)
            } != 0);
    assert!(unsafe {
                kernel32::CreatePipe(&mut rChildStdin, &mut wChildStdin, &mut saAttr, 0)
            } != 0);

    {
        println!("Launching AppContainer with redirected stdin/stdout/stderr");
        let launch_result = profile.launch(rChildStdin, wChildStdout, dir_path.to_str().unwrap());
        assert!(launch_result.is_ok());

        let hProcess = launch_result.unwrap();

        let mut dwRead: DWORD = 0 as DWORD;
        let mut buffer: Vec<u8> = Vec::with_capacity(37);

        println!("Reading 37 bytes for testing");
        assert!(unsafe {
                    kernel32::ReadFile(rChildStdout,
                                       buffer.as_mut_ptr() as LPVOID,
                                       37,
                                       &mut dwRead,
                                       mem::transmute::<usize, winapi::LPOVERLAPPED>(0))
                } != 0);

        let data;
        unsafe {
            let p = buffer.as_mut_ptr();
            mem::forget(buffer);

            data = Vec::from_raw_parts(p, dwRead as usize, 37);
        }

        let result = String::from_utf8(data);
        assert!(result.is_ok());

        let read_data = result.unwrap();

        println!("Read bytes: {:?}", &read_data);
        assert_eq!(read_data, "Wecome to the Greenhorn CSAW service!");
        assert!(unsafe { kernel32::TerminateProcess(hProcess.raw, 0xffffffff) } != 0);
    }
}