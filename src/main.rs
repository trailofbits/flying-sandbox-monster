#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

extern crate clap;
extern crate env_logger;

extern crate winapi;
extern crate kernel32;
extern crate serde;
extern crate serde_json;

#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate log;

mod acl;
mod appcontainer;
mod detours;
mod mpengine;
mod winffi;

use std::env;
use std::fs;
use std::process;
use std::path::{Path, PathBuf};
use std::ptr::null_mut;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::iter::once;

use clap::{Arg, App};
use winapi::{HANDLE, INVALID_HANDLE_VALUE, INFINITE, FILE_ATTRIBUTE_NORMAL, GENERIC_READ,
             FILE_SHARE_READ, OPEN_EXISTING};
use winffi::HANDLE_FLAG_INHERIT;

const kWorkerEnvVar: &'static str = "MPCLIENT_RS_WORKER";
const kWorkerPathEnvVar: &'static str = "MPCLIENT_RS_TARGET";

struct SupportFiles {
    files_to_fix: Vec<String>,
    sid: String,
}

fn add_acl_entry(path: &str, sid: &str) -> bool {
    let result = acl::SimpleDacl::from_path(path);
    if let Err(x) = result {
        error!("Failed to get ACL from {:?}: error={:}", path, x);
        return false;
    }

    let mut dacl = result.unwrap();

    if dacl.entry_exists(sid, acl::ACCESS_ALLOWED).is_some() {
        if !dacl.remove_entry(sid, acl::ACCESS_ALLOWED) {
            error!("Failed to remove existing ACL entry for AppContainer SID");
            return false;
        }
    }

    if !dacl.add_entry(acl::AccessControlEntry {
                           entryType: acl::ACCESS_ALLOWED,
                           flags: 0,
                           mask: winapi::GENERIC_READ | winapi::GENERIC_EXECUTE,
                           sid: sid.to_string(),
                       }) {
        error!("Failed to add AppContainer profile ACL entry from {:?}",
               path);
        return false;
    }

    match dacl.apply_to_path(path) {
        Ok(_) => {
            info!("  Added ACL entry for AppContainer profile in {:?}", path);
        }
        Err(x) => {
            error!("Failed to set new ACL into {:?}: error={:}", path, x);
            return false;
        }
    }

    true
}

fn del_acl_entry(path: &str, sid: &str) -> bool {
    let result = acl::SimpleDacl::from_path(path);
    if let Err(x) = result {
        error!("Failed to get ACL from {:?}: error={:}", path, x);
        return false;
    }

    let mut dacl = result.unwrap();

    if !dacl.remove_entry(sid, acl::ACCESS_ALLOWED) {
        error!("Failed to remove AppContainer profile ACL entry from {:?}",
               path);
        return false;
    }

    match dacl.apply_to_path(path) {
        Ok(_) => {
            info!("  Removed ACL entry for AppContainer profile in {:?}", path);
        }
        Err(x) => {
            error!("Failed to set new ACL into {:?}: error={:}", path, x);
            return false;
        }
    }

    true
}

impl SupportFiles {
    fn from(support_path: &Path, sid: &str) -> Option<SupportFiles> {
        let paths = match fs::read_dir(support_path) {
            Ok(val) => val,
            Err(_) => return None,
        };
        let mut obj = SupportFiles {
            files_to_fix: Vec::new(),
            sid: sid.to_string(),
        };
        if add_acl_entry(support_path.to_str().unwrap(), sid) {
            info!("Added ACL for directory {:?}", support_path);
            obj.files_to_fix
                .push(support_path.to_str().unwrap().to_string());
        }

        for path_item in paths {
            match path_item {
                Ok(val) => {
                    let path = val.path();
                    let path_str = path.to_str().unwrap();

                    if add_acl_entry(path_str, sid) {
                        info!("Added ACL for {:?} in {:?}", path_str, sid);
                        obj.files_to_fix.push(path_str.to_string());
                    }
                }
                Err(_) => {}
            }
        }

        Some(obj)
    }

    fn is_valid(&self) -> bool {
        self.files_to_fix.len() >= 7
    }
}

impl Drop for SupportFiles {
    fn drop(&mut self) {
        for path in self.files_to_fix.iter() {
            del_acl_entry(&path, &self.sid);
            info!("Removed ACL for {:?} in {:?}", self.sid, path);
        }
    }
}

impl Drop for appcontainer::Profile {
    fn drop(&mut self) {
        appcontainer::Profile::remove(&self.profile);
        info!("Removing AppContainer profile {:}", self.profile);
    }
}

fn parse_rw_handles(raw_values: &str) -> Option<(HANDLE, HANDLE)> {
    let result: Vec<&str> = raw_values.split(':').collect();
    if result.len() != 2 {
        return None;
    }

    let hRead: HANDLE = match result[0].parse::<usize>() {
        Ok(val) => val as HANDLE,
        Err(_) => return None,
    };

    let hWrite: HANDLE = match result[1].parse::<usize>() {
        Ok(val) => val as HANDLE,
        Err(_) => return None,
    };

    Some((hRead, hWrite))
}

fn do_worker(raw_values: &str) -> i32 {
    let support_path = get_support_path().unwrap();

    let (hRead, hWrite) = match parse_rw_handles(raw_values) {
        Some((x, y)) => (x, y),
        None => return -1,
    };

    let mut mpengine_path = support_path.clone();
    mpengine_path.push("mpengine.dll");
    if !mpengine_path.exists() {
        return -1;
    }

    let mut engine = match mpengine::MpEngine::load(mpengine_path.to_str().unwrap()) {
        Some(x) => x,
        None => {
            return -1;
        }
    };
    let ptr = mpengine::USERPTR_HANDLES {
        hRead: hRead,
        hWrite: hWrite,
    };

    if !engine.scan(&ptr) {
        return -1;
    }


    // TODO: Send a NULL message to exit?

    0
}

fn get_support_path() -> Option<PathBuf> {
    let mut dir_path = match env::current_exe() {
        Ok(x) => x,
        Err(_) => return None,
    };

    while dir_path.pop() {
        dir_path.push("support");
        if dir_path.exists() && dir_path.is_dir() {
            return Some(dir_path);
        }
        dir_path.pop();
    }

    None
}

fn event_loop(profile_name: &str, target_path: &Path) -> i32 {
    let child_path = match env::current_exe() {
        Ok(x) => x,
        Err(_) => {
            error!("Failed to get current module path!");
            return -1;
        }
    };

    info!("profile_name = {:}", profile_name);
    info!("target_path  = {:?}", target_path);
    info!("child_path = {:?}", child_path);

    // XXX: Watch out for the unwrap()
    let profile = match appcontainer::Profile::new(profile_name, child_path.to_str().unwrap()) {
        Ok(val) => {
            info!("New AppContainer profile created!");
            val
        }
        Err(x) => {
            error!("Failed to create AppContainer profile for {:}: GLE={:}",
                   profile_name,
                   x);
            return -1;
        }
    };

    let support_path = match get_support_path() {
        Some(val) => val,
        None => {
            error!("Failed to find support/ directory containing mpengine.dll");
            return -1;
        }
    };

    info!("profile SID = {:?}", profile.sid);
    info!("support_path = {:?}", support_path);

    let support_files = match SupportFiles::from(&support_path, &profile.sid) {
        Some(val) => val,
        None => {
            error!("Failed to set ACLs for support files in {:?}", support_path);
            return -1;
        }
    };

    if !support_files.is_valid() {
        error!("Not enough support files in {:?}, did you follow instructions on extracting?",
               support_path);
        return -1;
    }

#[allow(unused_assignments)]
    let mut hFile: HANDLE = INVALID_HANDLE_VALUE;
    let mut hChildRead: HANDLE = INVALID_HANDLE_VALUE;
    let mut hChildWrite: HANDLE = INVALID_HANDLE_VALUE;

    if unsafe { kernel32::CreatePipe(&mut hChildRead, &mut hChildWrite, null_mut(), 0) } == 0 {
        error!("Failed to create pipe: GLE={:}",
               unsafe { kernel32::GetLastError() });
        return -1;
    }

    if unsafe { kernel32::SetHandleInformation(hChildRead, HANDLE_FLAG_INHERIT, 0) } == 0 {
        error!("Failed to set child read handle to non-inherit: GLE={:}",
               unsafe { kernel32::GetLastError() });
        return -1;
    }

    let wPath: Vec<u16> = OsStr::new(target_path.to_str().unwrap())
        .encode_wide()
        .chain(once(0))
        .collect();

    hFile = unsafe {
        kernel32::CreateFileW(wPath.as_ptr(),
                              GENERIC_READ,
                              FILE_SHARE_READ,
                              null_mut(),
                              OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL,
                              null_mut())
    };
    if hFile == INVALID_HANDLE_VALUE {
        error!("Specified file '{:?}' is invalid", target_path);
        return -1;
    }

    if unsafe { kernel32::SetHandleInformation(hChildWrite, HANDLE_FLAG_INHERIT, 1) } == 0 {
        error!("Failed to set child write handle to inherit: GLE={:}",
               unsafe { kernel32::GetLastError() });
        return -1;
    }

    if unsafe { kernel32::SetHandleInformation(hFile, HANDLE_FLAG_INHERIT, 1) } == 0 {
        error!("Failed to set child file handle to inherit: GLE={:}",
               unsafe { kernel32::GetLastError() });
        return -1;
    }

    env::set_var(kWorkerEnvVar,
                 format!("{:}:{:}", hFile as usize, hChildWrite as usize));
    env::set_var(kWorkerPathEnvVar, target_path.to_str().unwrap());
    let process_handle =
        match profile.launch(INVALID_HANDLE_VALUE,
                             INVALID_HANDLE_VALUE,
                             support_path.to_str().unwrap()) {
            Ok(val) => {
                unsafe { kernel32::CloseHandle(hChildWrite) };
                unsafe { kernel32::CloseHandle(hFile) };

                env::remove_var(kWorkerEnvVar);
                env::remove_var(kWorkerPathEnvVar);
                info!("Child AppContainer'd process launched!");
                val
            }
            Err(x) => {
                unsafe { kernel32::CloseHandle(hChildWrite) };
                unsafe { kernel32::CloseHandle(hChildRead) };
                unsafe { kernel32::CloseHandle(hFile) };

                env::remove_var(kWorkerEnvVar);
                env::remove_var(kWorkerPathEnvVar);
                error!("Failed to launch sandboxed process! GLE={:}", x);
                return -1;
            }
        };

    println!("{:?}", mpengine::read_scan_response(hChildRead));
    println!("{:?}", mpengine::read_scan_response(hChildRead));

    unsafe { kernel32::WaitForSingleObject(process_handle.raw, INFINITE) };

    0
}

fn do_main() -> i32 {
    let matches = App::new("mpclient-rs")
        .author("yying <andy@trailofbits.com>")
        .about("Sandboxed Microsoft Defender scanning engine example")
        .arg(Arg::with_name("name")
                 .short("n")
                 .long("name")
                 .value_name("NAME")
                 .default_value("default_msmpeng_profile")
                 .help("AppContainer profile name"))
        .arg(Arg::with_name("path")
                 .index(1)
                 .required(true)
                 .help("Path to file to scan"))
        .get_matches();

    if let Err(_) = env_logger::init() {
        error!("Failed to initialize env_logger!");
        return -1;
    }

    let target_path = Path::new(matches.value_of("path").unwrap());
    if !target_path.exists() {
        error!("File to scan does not exist: {:?}", target_path);
        return -1;
    }

    event_loop(matches.value_of("name").unwrap(), target_path)
}

fn main() {
    process::exit(match env::var(kWorkerEnvVar) {
                      Ok(val) => do_worker(&val),
                      Err(_) => do_main(),
                  });
}
