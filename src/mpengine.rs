#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(dead_code)]

extern crate winapi;
extern crate kernel32;
extern crate libc;
extern crate widestring;
extern crate serde;
extern crate serde_json;

#[allow(unused_imports)]
use log::*;
use winapi::*;

#[allow(unused_imports)]
use std::env;

use std::str;
use std::path::PathBuf;
use std::ffi::{OsStr, CStr, CString};
use std::os::windows::ffi::OsStrExt;
use std::iter::once;
use std::mem;
use std::ptr::null_mut;

use super::detours::Module;

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

pub const RSIG_BASE: u32 = 0x4000;
pub const RSIG_RESERVED1: u32 = 0x4003;
pub const RSIG_GETEINFO: u32 = 0x4004;
pub const RSIG_VIRINFO: u32 = 0x4005;
pub const RSIG_UNLOADENGINE: u32 = 0x400A;
pub const RSIG_RESERVED2: u32 = 0x400B;
pub const RSIG_SCANFILE_TS_W: u32 = 0x4014;
pub const RSIG_SCANPATH_TS_W: u32 = 0x4015;
pub const RSIG_RESERVED3: u32 = 0x4019;
pub const RSIG_CONFIGURE_NEW_W: u32 = 0x401A;
pub const RSIG_RESERVED4: u32 = 0x401C;
pub const RSIG_FIW32_CONFIG: u32 = 0x401D;
pub const RSIG_SPLIT_VIRNAME: u32 = 0x401E;
pub const RSIG_HOOK_API: u32 = 0x401F;
pub const RSIG_INIT_ENGINE_CONTEXT: u32 = 0x4020;
pub const RSIG_CLEANUP_ENGINE_CONTEXT: u32 = 0x4021;
pub const RSIG_SCANFILE_TS_WCONTEXT: u32 = 0x4023;
pub const RSIG_SCANPATH_TS_WCONTEXT: u32 = 0x4024;
pub const RSIG_VIRINFO_FILTERED: u32 = 0x4025;
pub const RSIG_SCAN_OPEN: u32 = 0x4026;
pub const RSIG_SCAN_GETEVENT: u32 = 0x4027;
pub const RSIG_SCAN_CLOSE: u32 = 0x4028;
pub const RSIG_GET_THREAT_INFO: u32 = 0x4030;
pub const RSIG_SCANSTREAMW: u32 = 0x4031;
pub const RSIG_SCANSTREAMW_WCONTEXT: u32 = 0x4032;
pub const RSIG_CHECK_PRIVILEGES: u32 = 0x4033;
pub const RSIG_ADJUST_PRIVILEGES: u32 = 0x4034;
pub const RSIG_SET_FILECHANGEQUERY: u32 = 0x4035;
pub const RSIG_BOOTENGINE: u32 = 0x4036;
pub const RSIG_RTP_GETINITDATA: u32 = 0x4037;
pub const RSIG_RTP_SETEVENTCALLBACK: u32 = 0x4038;
pub const RSIG_RTP_NOTIFYCHANGE: u32 = 0x4039;
pub const RSIG_RTP_GETBEHAVIORCONTEXT: u32 = 0x403A;
pub const RSIG_RTP_SETBEHAVIORCONTEXT: u32 = 0x403B;
pub const RSIG_RTP_FREEBEHAVIORCONTEXT: u32 = 0x403C;
pub const RSIG_SCAN_STREAMBUFFER: u32 = 0x403D;
pub const RSIG_RTP_STARTBEHAVIORMONITOR: u32 = 0x403E;
pub const RSIG_RTP_STOPBEHAVIORMONITOR: u32 = 0x403F;
pub const RSIG_GET_SIG_DATA: u32 = 0x4041;
pub const RSIG_VALIDATE_FEATURE: u32 = 0x4042;
pub const RSIG_SET_CALLBACK: u32 = 0x4043;
pub const RSIG_OBFUSCATE_DATA: u32 = 0x4044;
pub const RSIG_DROP_BMDATA: u32 = 0x4045;
pub const RSIG_SCANEXTRACT: u32 = 0x4046;
pub const RSIG_CHANGE_SETTINGS: u32 = 0x4047;
pub const RSIG_RTSIG_DATA: u32 = 0x4048;
pub const RSIG_SYSTEM_REBOOT: u32 = 0x4049;
pub const RSIG_REVOKE_QUERY: u32 = 0x4050;
pub const RSIG_CHECK_EXCLUSIONS: u32 = 0x4051;
pub const RSIG_COMPLETE_INITIALIZATION: u32 = 0x4052;
pub const RSIG_STATE_CHANGE: u32 = 0x4053;
pub const RSIG_SEND_CALLISTO_TELEMETRY: u32 = 0x4054;
pub const RSIG_DYNAMIC_CONFIG: u32 = 0x4055;
pub const RSIG_SEND_EARLY_BOOT_DATA: u32 = 0x4056;
pub const RSIG_SCAN_TCG_LOG: u32 = 0x4057;
pub const RSIG_CANCEL_ENGINE_LOAD: u32 = 0x4058;
pub const RSIG_SQM_CONFIG: u32 = 0x4059;
pub const RSIG_SERVICE_NOTIFICATION: u32 = 0x405A;
pub const RSIG_SCAN_TCG_LOG_EX: u32 = 0x405B;
pub const RSIG_FREE_TCG_EXTENDED_DATA: u32 = 0x405C;
pub const RSIG_NOTIFY_MAINTENANCE_WINDOW_STATE: u32 = 0x405D;
pub const RSIG_SEND_REMOTE_ATTESTATION_DATA: u32 = 0x405E;
pub const RSIG_SUSPICIOUS_SCAN: u32 = 0x405F;
pub const RSIG_ON_CLOUD_COMPLETION: u32 = 0x4060;
pub const RSIG_CONTROL_SPLI: u32 = 0x4061;
pub const RSIG_THREAT_UPDATE_STATUS: u32 = 0x4062;
pub const RSIG_VERIFY_MACHINE_GUID: u32 = 0x4063;
pub const RSIG_NRI_UPDATE_STATE: u32 = 0x4064;
pub const RSIG_TPM_CONFIG: u32 = 0x4065;
pub const RSIG_GET_RESOURCE_INFO: u32 = 0x4066;
pub const RSIG_GET_ASYNC_QUEUE_LENGTH: u32 = 0x4067;
pub const RSIG_RTP_IMAGENAME_CONFIG: u32 = 0x4068;
pub const RSIG_SET_CUSTOM_SET_ID: u32 = 0x4069;
pub const RSIG_CONFIGURE_ROLES: u32 = 0x4070;
pub const RSIG_HOOK_WOW: u32 = 0x4071;
pub const RSIG_AMSI_SESSION_END: u32 = 0x4072;
pub const RSIG_RESOURCE_CONTEXT_CONSOLIDATION: u32 = 0x4073;

pub const BOOTENGINE_PARAMS_VERSION: u32 = 0x8E00;

pub const OPENSCAN_VERSION: u32 = 0x2C6D;

pub enum ScanSource {
    SCANSOURCE_NOTASOURCE = 0,
    SCANSOURCE_SCHEDULED = 1,
    SCANSOURCE_ONDEMAND = 2,
    SCANSOURCE_RTP = 3,
    SCANSOURCE_IOAV_WEB = 4,
    SCANSOURCE_IOAV_FILE = 5,
    SCANSOURCE_CLEAN = 6,
    SCANSOURCE_UCL = 7,
    SCANSOURCE_RTSIG = 8,
    SCANSOURCE_SPYNETREQUEST = 9,
    SCANSOURCE_INFECTIONRESCAN = 0x0A,
    SCANSOURCE_CACHE = 0x0B,
    SCANSOURCE_UNK_TELEMETRY = 0x0C,
    SCANSOURCE_IEPROTECT = 0x0D,
    SCANSOURCE_ELAM = 0x0E,
    SCANSOURCE_LOCAL_ATTESTATION = 0x0F,
    SCANSOURCE_REMOTE_ATTESTATION = 0x10,
    SCANSOURCE_HEARTBEAT = 0x11,
    SCANSOURCE_MAINTENANCE = 0x12,
    SCANSOURCE_MPUT = 0x13,
    SCANSOURCE_AMSI = 0x14,
    SCANSOURCE_STARTUP = 0x15,
    SCANSOURCE_ADDITIONAL_ACTIONS = 0x16,
    SCANSOURCE_AMSI_UAC = 0x17,
    SCANSOURCE_GENSTREAM = 0x18,
    SCANSOURCE_REPORTINTERNALDETECTION = 0x19,
    SCANSOURCE_SENSE = 0x1A,
    SCANSOURCE_XBAC = 0x1B,
}

pub enum Boot {
    BOOT_CACHEENABLED = 1 << 0,
    BOOT_NOFILECHANGES = 1 << 3,
    BOOT_ENABLECALLISTO = 1 << 6,
    BOOT_REALTIMESIGS = 1 << 8,
    BOOT_DISABLENOTIFICATION = 1 << 9,
    BOOT_CLOUDBHEAVIORBLOCK = 1 << 10,
    BOOT_ENABLELOGGING = 1 << 12,
    BOOT_ENABLEBETA = 1 << 16,
    BOOT_ENABLEIEV = 1 << 17,
    BOOT_ENABLEMANAGED = 1 << 19,
}

pub enum BootAttr {
    BOOT_ATTR_NORMAL = 1 << 0,
    BOOT_ATTR_ISXBAC = 1 << 2,
}

#[allow(dead_code)]
pub enum Engine {
    ENGINE_UNPACK = 1 << 1,
    ENGINE_HEURISTICS = 1 << 3,
    ENGINE_DISABLETHROTTLING = 1 << 11,
    ENGINE_PARANOID = 1 << 12,
    ENGINE_DISABLEANTISPYWARE = 1 << 15,
    ENGINE_DISABLEANTIVIRUS = 1 << 16,
    ENGINE_DISABLENETWORKDRIVES = 1 << 20,
}

#[allow(dead_code)]
pub enum Scan {
    SCAN_FILENAME = 1 << 8,
    SCAN_ENCRYPTED = 1 << 6,
    SCAN_MEMBERNAME = 1 << 7,
    SCAN_FILETYPE = 1 << 9,
    SCAN_TOPLEVEL = 1 << 18,
    SCAN_PACKERSTART = 1 << 19,
    SCAN_PACKEREND = 1 << 12,
    SCAN_ISARCHIVE = 1 << 16,
    SCAN_VIRUSFOUND = 1 << 27,
    SCAN_CORRUPT = 1 << 13,
    SCAN_UNKNOWN = 1 << 15,
}

#[allow(dead_code)]
pub enum StreamAttr {
    STREAM_ATTRIBUTE_INVALID = 0,
    STREAM_ATTRIBUTE_SKIPBMNOTIFICATION = 1,
    STREAM_ATTRIBUTE_BMDATA = 2,
    STREAM_ATTRIBUTE_FILECOPYPERFHINT = 3,
    STREAM_ATTRIBUTE_FILECOPYSOURCEPATH = 4,
    STREAM_ATTRIBUTE_FILECHANGEPERFHINT = 5,
    STREAM_ATTRIBUTE_FILEOPPROCESSID = 6,
    STREAM_ATTRIBUTE_FILEBACKUPWRITEPERFHINT = 7,
    STREAM_ATTRIBUTE_DONOTCACHESCANRESULT = 8,
    STREAM_ATTRIBUTE_SCANREASON = 9,
    STREAM_ATTRIBUTE_FILEID = 10,
    STREAM_ATTRIBUTE_FILEVOLUMESERIALNUMBER = 11,
    STREAM_ATTRIBUTE_FILEUSN = 12,
    STREAM_ATTRIBUTE_SCRIPTTYPE = 13,
    STREAM_ATTRIBUTE_PRIVATE = 14,
    STREAM_ATTRIBUTE_URL = 15,
    STREAM_ATTRIBUTE_REFERRALURL = 16,
    STREAM_ATTRIBUTE_SCRIPTID = 17,
    STREAM_ATTRIBUTE_HOSTAPPVERSION = 18,
    STREAM_ATTRIBUTE_THREAT_ID = 19,
    STREAM_ATTRIBUTE_THREAT_STATUS = 21,
    STREAM_ATTRIBUTE_LOFI = 22,
    STREAM_ATTRIBUTE_THREAT_RESOURCES = 25,
    STREAM_ATTRIBUTE_LOFI_RESOURCES = 26,
    STREAM_ATTRIBUTE_VOLATILE = 29,
    STREAM_ATTRIBUTE_REFERRERURL = 30,
    STREAM_ATTRIBUTE_REQUESTORMODE = 31,
    STREAM_ATTRIBUTE_CI_EA = 33,
    STREAM_ATTRIBUTE_CURRENT_FILEUSN = 34,
    STREAM_ATTRIBUTE_AVAILABLE_DSS_THREADS = 35,
    STREAM_ATTRIBUTE_IO_STATUS_BLOCK_FOR_NEW_FILE = 36,
    STREAM_ATTRIBUTE_DESIRED_ACCESS = 37,
    STREAM_ATTRIBUTE_FILEOPPROCESSNAME = 38,
    STREAM_ATTRIBUTE_DETAILED_SCAN_NEEDED = 39,
    STREAM_ATTRIBUTE_URL_HAS_GOOD_REPUTATION = 40,
    STREAM_ATTRIBUTE_SITE_HAS_GOOD_REPUTATION = 41,
    STREAM_ATTRIBUTE_URL_ZONE = 42,
    STREAM_ATTRIBUTE_CONTROL_GUID = 43,
    STREAM_ATTRIBUTE_CONTROL_VERSION = 44,
    STREAM_ATTRIBUTE_CONTROL_PATH = 45,
    STREAM_ATTRIBUTE_CONTROL_HTML = 46,
    STREAM_ATTRIBUTE_PAGE_CONTEXT = 47,
    STREAM_ATTRIBUTE_FRAME_URL = 48,
    STREAM_ATTRIBUTE_FRAME_HTML = 49,
    STREAM_ATTRIBUTE_ACTION_IE_BLOCK_PAGE = 50,
    STREAM_ATTRIBUTE_ACTION_IE_BLOCK_CONTROL = 51,
    STREAM_ATTRIBUTE_SHARE_ACCESS = 52,
    STREAM_ATTRIBUTE_OPEN_OPTIONS = 53,
    STREAM_ATTRIBUTE_DEVICE_CHARACTERISTICS = 54,
    STREAM_ATTRIBUTE_FILE_ATTRIBUTES = 55,
    STREAM_ATTRIBUTE_HAS_MOTW_ADS = 56,
    STREAM_ATTRIBUTE_SE_SIGNING_LEVEL = 57,
    STREAM_ATTRIBUTE_SESSION_ID = 58,
    STREAM_ATTRIBUTE_AMSI_APP_ID = 59,
    STREAM_ATTRIBUTE_AMSI_SESSION_ID = 60,
    STREAM_ATTRIBUTE_FILE_OPERATION_PPID = 61,
    STREAM_ATTRIBUTE_SECTOR_NUMBER = 62,
    STREAM_ATTRIBUTE_AMSI_CONTENT_NAME = 63,
    STREAM_ATTRIBUTE_AMSI_UAC_REQUEST_CONTEXT = 64,
    STREAM_ATTRIBUTE_RESOURCE_CONTEXT = 65,
    STREAM_ATTRIBUTE_OPEN_CREATEPROCESS_HINT = 66,
    STREAM_ATTRIBUTE_GENSTREAM_APP_NAME = 67,
    STREAM_ATTRIBUTE_GENSTREAM_SESSION_ID = 68,
    STREAM_ATTRIBUTE_GENSTREAM_CONTENT_NAME = 69,
    STREAM_ATTRIBUTE_OPEN_ACCESS_STATE_FLAGS = 70,
    STREAM_ATTRIBUTE_GENSTREAM_EXTERN_GUID = 71,
    STREAM_ATTRIBUTE_IS_CONTAINER_FILE = 72,
    STREAM_ATTRIBUTE_AMSI_REDIRECT_CHAIN = 75,
}

#[allow(dead_code)]
pub enum ScanReason {
    SCANREASON_UNKNOWN = 0,
    SCANREASON_ONMOUNT = 1,
    SCANREASON_ONOPEN = 2,
    SCANREASON_ONFIRSTREAD = 3,
    SCANREASON_ONWRITE = 4,
    SCANREASON_ONMODIFIEDHANDLECLOSE = 5,
    SCANREASON_INMEMORY = 8,
    SCANREASON_VALIDATION_PRESCAN = 9,
    SCANREASON_VALIDATION_CONTENTSCAN = 0x0A,
    SCANREASON_ONVOLUMECLEANUP = 0x0B,
    SCANREASON_AMSI = 0x0C,
    SCANREASON_AMSI_UAC = 0x0D,
    SCANREASON_GENERICSTREAM = 0x0E,
    SCANREASON_IOAVSTREAM = 0x0F,
}

DEF_STRUCT!{struct ENGINE_INFO {
  field_0: DWORD,
  field_4: DWORD,
  field_8: DWORD,
  field_C: DWORD,
}}
pub type PENGINE_INFO = *mut ENGINE_INFO;

DEF_STRUCT!{struct ENGINE_CONFIG {
  EngineFlags: DWORD,
  Inclusions: PWCHAR,
  Exceptions: PVOID,
  UnknownString2: PWCHAR,
  QuarantineLocation: PWCHAR,
  field_14: DWORD,
  field_18: DWORD,
  field_1C: DWORD,
  field_20: DWORD,
  field_24: DWORD,
  field_28: DWORD,
  field_2C: DWORD,
  field_30: DWORD,
  field_34: DWORD,
  UnknownAnsiString1: PCHAR,
  UnknownAnsiString2: PCHAR,
}}
pub type PENGINE_CONFIG = *mut ENGINE_CONFIG;

DEF_STRUCT!{struct ENGINE_CONTEXT {
  field_0: DWORD,
}}
pub type PENGINE_CONTEXT = *mut ENGINE_CONTEXT;

DEF_STRUCT!{struct BOOTENGINE_PARAMS {
  ClientVersion: DWORD,
  SignatureLocation: PWCHAR,
  SpynetSource: PVOID,
  EngineConfig: PENGINE_CONFIG,
  EngineInfo: PENGINE_INFO,
  ScanReportLocation: PWCHAR,
  BootFlags: DWORD,
  LocalCopyDirectory: PWCHAR,
  OfflineTargetOS: PWCHAR,
  ProductString: [CHAR; 16],
  field_34: DWORD,
  GlobalCallback: PVOID,
  EngineContext: PENGINE_CONTEXT,
  AvgCpuLoadFactor: DWORD,
  field_44: [CHAR; 16],
  SpynetReportingGUID: PWCHAR,
  SpynetVersion: PWCHAR,
  NISEngineVersion: PWCHAR,
  NISSignatureVersion: PWCHAR,
  FlightingEnabled: DWORD,
  FlightingLevel: DWORD,
  DynamicConfig: PVOID,
  AutoSampleSubmission: DWORD,
  EnableThreatLogging: DWORD,
  ProductName: PWCHAR,
  PassiveMode: DWORD,
  SenseEnabled: DWORD,
  SenseOrgId: PWCHAR,
  Attributes: DWORD,
  BlockAtFirstSeen: DWORD,
  PUAProtection: DWORD,
  SideBySidePassiveMode: DWORD,
}}
pub type PBOOTENGINE_PARAMS = *mut BOOTENGINE_PARAMS;

DEF_STRUCT!{struct OPENSCAN_PARAMS {
  Version: DWORD,
  ScanSource: DWORD,
  Flags: DWORD,
  field_C: DWORD,
  field_10: DWORD,
  field_14: DWORD,
  field_18: DWORD,
  field_1C: DWORD,
  ScanID: GUID,
  field_30: DWORD,
  field_34: DWORD,
  field_38: DWORD,
  field_3C: DWORD,
  field_40: DWORD,
  field_44: DWORD,
}}
#[allow(dead_code)]
pub type POPENSCAN_PARAMS = *mut OPENSCAN_PARAMS;

DEF_STRUCT!{struct SCANSTRUCT {
  field_0: DWORD,
  Flags: DWORD,
  FileName: PCHAR,
  VirusName: [UCHAR; 28],
  field_28: DWORD,
  field_2C: DWORD,
  field_30: DWORD,
  field_34: DWORD,
  field_38: DWORD,
  field_3C: DWORD,
  field_40: DWORD,
  field_44: DWORD,
  field_48: DWORD,
  field_4C: DWORD,
  FileSize: DWORD,
  field_54: DWORD,
  UserPtr: PVOID,
  field_5C: DWORD,
  MaybeFileName2: PCHAR,
  StreamName1: PWCHAR,
  StreamName2: PWCHAR,
  field_6C: DWORD,
  ThreatId: DWORD,
}}
pub type PSCANSTRUCT = *mut SCANSTRUCT;

DEF_STRUCT!{struct SCAN_REPLY {
  EngineScanCallback: extern fn(this: PSCANSTRUCT) -> DWORD,
  field_4: DWORD,
  UserPtr: PVOID,
  field_C: DWORD,
}}
pub type PSCAN_REPLY = *mut SCAN_REPLY;

DEF_STRUCT!{struct SCANSTREAM_PARAMS {
  Descriptor: PSTREAMBUFFER_DESCRIPTOR,
  ScanReply: PSCAN_REPLY,
  UnknownB: DWORD,
  UnknownC: DWORD,
}}
pub type PSCANSTREAM_PARAMS = *mut SCANSTREAM_PARAMS;

DEF_STRUCT!{struct STREAMBUFFER_DESCRIPTOR {
  UserPtr: PVOID,
  Read: extern fn(this: PVOID, Offset: DWORD64, Buffer: PVOID, Size: DWORD, SizeRead: PDWORD) -> DWORD,
  Write: extern fn(this: PVOID, Offset: DWORD64, Buffer: PVOID, Size: DWORD, TotalWritten: PDWORD) -> DWORD,
  GetSize: extern fn(this: PVOID, FileSize: PDWORD64) -> DWORD,
  SetSize: extern fn(this: PVOID, FileSize: PDWORD64) -> DWORD,
  GetName: extern fn(this: PVOID) -> PWCHAR,
  SetAttributes: extern fn(this: PVOID, Attribute: DWORD, Data: PVOID, DataSize: DWORD) -> DWORD,
  GetAttributes: extern fn(this: PVOID, Attribute: DWORD, Data: PVOID, DataSize: DWORD, DataSizeWritten: PDWORD) -> DWORD,
}}
pub type PSTREAMBUFFER_DESCRIPTOR = *mut STREAMBUFFER_DESCRIPTOR;

DEF_STRUCT!{struct USERPTR_HANDLES {
    hRead: HANDLE,
    hWrite: HANDLE,
}}

#[derive(Serialize, Deserialize, Debug)]
pub struct ScanReplyMsg {
    Flags: u32,
    FileName: String,
    VirusName: String,
}

pub type rsignalFnType = extern "C" fn(KernelHandle: PHANDLE,
                                       Code: DWORD,
                                       Params: PVOID,
                                       Size: DWORD)
                                       -> DWORD;

#[allow(dead_code)]
pub struct MpEngine {
    DllModule: HMODULE,
    SignatureLocation: Vec<u16>,
    ProductName: Vec<u16>,
    QuarantineLocation: Vec<u16>,
    Inclusions: Vec<u16>,
    BootParams: BOOTENGINE_PARAMS,
    EngineConfig: ENGINE_CONFIG,
    EngineInfo: ENGINE_INFO,
    KernelHandle: HANDLE,
    rsignal: rsignalFnType,
}

#[cfg(test)]
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

const kStreamName: &'static [u16] = &[105, 110, 112, 117, 116, 0];

extern "C" fn doRead(this: PVOID,
                     Offset: DWORD64,
                     Buffer: PVOID,
                     Size: DWORD,
                     SizeRead: PDWORD)
                     -> DWORD {
    let ptr: *const USERPTR_HANDLES =
        unsafe { mem::transmute::<PVOID, *const USERPTR_HANDLES>(this) };
    if unsafe {
           kernel32::SetFilePointerEx((*ptr).hRead, Offset as i64, null_mut(), FILE_BEGIN)
       } == 0 {
        return 0;
    }

    unsafe { kernel32::ReadFile((*ptr).hRead, Buffer, Size, SizeRead, null_mut()) as DWORD }
}

extern "C" fn doGetSize(this: PVOID, FileSize: PDWORD64) -> DWORD {
    let ptr: *const USERPTR_HANDLES =
        unsafe { mem::transmute::<PVOID, *const USERPTR_HANDLES>(this) };

    unsafe { kernel32::GetFileSizeEx((*ptr).hRead, FileSize as *mut i64) as DWORD }
}

#[allow(unused_variables)]
extern "C" fn doGetName(this: PVOID) -> PWCHAR {
    kStreamName.as_ptr() as PWCHAR
}

extern "C" fn doScanCallback(this: PSCANSTRUCT) -> DWORD {
    let ptr: *const USERPTR_HANDLES =
        unsafe { mem::transmute::<PVOID, *const USERPTR_HANDLES>((*this).UserPtr) };

    let VirusNameRaw = unsafe { (*this).VirusName };
    let end_idx = match VirusNameRaw.iter().position(|&x| x == 0) {
        Some(x) => x,
        None => 28,
    };

    let VirusName = str::from_utf8(&VirusNameRaw[0..end_idx]).unwrap();
    let FileName = unsafe { CStr::from_ptr((*this).FileName) };

    let msg = ScanReplyMsg {
        Flags: unsafe { (*this).Flags },
        FileName: FileName.to_string_lossy().into_owned(),
        VirusName: VirusName.to_string(),
    };

    let serialized = serde_json::to_string(&msg).unwrap();
    let size: DWORD = serialized.len() as DWORD;
    let bytes = serialized.into_bytes();
    let mut writeSize: DWORD = 0 as DWORD;

    if unsafe {
           kernel32::WriteFile((*ptr).hWrite,
                               mem::transmute::<&DWORD, LPVOID>(&size),
                               mem::size_of::<DWORD>() as DWORD,
                               &mut writeSize,
                               null_mut())
       } == 0 {
        return 1;
    }

    if unsafe {
           kernel32::WriteFile((*ptr).hWrite,
                               mem::transmute::<*const u8, LPVOID>(bytes.as_ptr()),
                               size,
                               &mut writeSize,
                               null_mut())
       } == 0 {
        return 1;
    }
    0
}

#[allow(unused_variables)]
unsafe extern "system" fn ExceptionHandler(ExceptionInfo: PEXCEPTION_POINTERS) -> LONG {
    kernel32::TerminateProcess(kernel32::GetCurrentProcess(), 0);
    0
}

extern "system" fn myRtlGetVersion(lpVersionInformation: LPOSVERSIONINFOEXW) -> NTSTATUS {
    unsafe { (*lpVersionInformation).dwMajorVersion = 5 };
    unsafe { (*lpVersionInformation).dwMinorVersion = 1 };

    0
}

impl MpEngine {
    pub fn load(path: &str) -> Option<MpEngine> {
        let dll_path: Vec<u16> = OsStr::new(path).encode_wide().chain(once(0)).collect();
        let hModule = unsafe { kernel32::LoadLibraryW(dll_path.as_ptr()) };
        if hModule == (0 as HMODULE) {
            return None;
        }

        let target = match Module::target("mpengine.dll") {
            Some(x) => x,
            None => return None,
        };

        // XXX: We need to IAT hook RtlGetVersion so it reports as Windows XP in order to run
        //      within AppContainer
        target.intercept("ntdll.dll", "RtlGetVersion", unsafe {
            mem::transmute::<extern "system" fn(LPOSVERSIONINFOEXW)
                                                -> NTSTATUS,
                             LPVOID>(myRtlGetVersion)
        });

        let mut support_path = PathBuf::from(path);
        support_path.pop();

        let fnName = CString::new("__rsignal").unwrap();
        let fnptr = unsafe { kernel32::GetProcAddress(hModule, fnName.as_ptr()) };
        if fnptr == (0 as LPVOID) {
            return None;
        }

        let mut obj = MpEngine {
            DllModule: hModule,
            rsignal: unsafe { mem::transmute::<*const VOID, rsignalFnType>(fnptr) },
            SignatureLocation: OsStr::new(support_path.to_str().unwrap())
                .encode_wide()
                .chain(once(0))
                .collect(),
            ProductName: OsStr::new("Antivirus")
                .encode_wide()
                .chain(once(0))
                .collect(),
            QuarantineLocation: OsStr::new("quarantine")
                .encode_wide()
                .chain(once(0))
                .collect(),
            Inclusions: OsStr::new("*.*").encode_wide().chain(once(0)).collect(),
            BootParams: unsafe { mem::zeroed() },
            EngineConfig: unsafe { mem::zeroed() },
            EngineInfo: unsafe { mem::zeroed() },
            KernelHandle: 0 as HANDLE,
        };

        obj.BootParams.ClientVersion = BOOTENGINE_PARAMS_VERSION;
        obj.BootParams.Attributes = BootAttr::BOOT_ATTR_NORMAL as u32;
        obj.BootParams.SignatureLocation = obj.SignatureLocation.as_mut_ptr();
        obj.BootParams.ProductName = obj.ProductName.as_mut_ptr();
        obj.EngineConfig.QuarantineLocation = obj.QuarantineLocation.as_mut_ptr();
        obj.EngineConfig.Inclusions = obj.Inclusions.as_mut_ptr();
        obj.EngineConfig.EngineFlags = 1 << 1;
        obj.BootParams.EngineInfo = &mut obj.EngineInfo;
        obj.BootParams.EngineConfig = &mut obj.EngineConfig;

        let ret = unsafe {
            (obj.rsignal)(&mut obj.KernelHandle,
                          RSIG_BOOTENGINE,
                          mem::transmute::<PBOOTENGINE_PARAMS, PVOID>(&mut obj.BootParams),
                          mem::size_of::<BOOTENGINE_PARAMS>() as u32)
        };

        if ret != 0 {
            return None;
        }

        Some(obj)
    }

    pub fn scan(&mut self, ptr: &USERPTR_HANDLES) -> bool {
        let mut ScanReply: SCAN_REPLY = unsafe { mem::zeroed() };
        let mut ScanParams: SCANSTREAM_PARAMS = unsafe { mem::zeroed() };
        let mut ScanDescriptor: STREAMBUFFER_DESCRIPTOR = unsafe { mem::zeroed() };

        ScanParams.Descriptor = &mut ScanDescriptor;
        ScanParams.ScanReply = &mut ScanReply;
        ScanReply.EngineScanCallback = doScanCallback;
        ScanReply.field_C = 0x7fffffff;
        ScanReply.UserPtr = unsafe { mem::transmute::<&USERPTR_HANDLES, LPVOID>(ptr) };
        ScanDescriptor.Read = doRead;
        ScanDescriptor.GetSize = doGetSize;
        ScanDescriptor.GetName = doGetName;

        ScanDescriptor.UserPtr = unsafe { mem::transmute::<&USERPTR_HANDLES, LPVOID>(ptr) };

        let ret = unsafe {
            (self.rsignal)(&mut self.KernelHandle,
                           RSIG_SCAN_STREAMBUFFER,
                           mem::transmute::<PSCANSTREAM_PARAMS, LPVOID>(&mut ScanParams),
                           mem::size_of::<SCANSTREAM_PARAMS>() as u32)
        };
        if ret != 0 {
            return false;
        }

        true
    }
}

impl Drop for MpEngine {
    fn drop(&mut self) {
        // TODO: Maybe call RSIG_UNLOAD_ENGINE?

        // XXX: We set up an exception handler to catch a STATUS_INVALID_HANDLE.
        // We need to investigate why this occurs but for now, just terminate process
        unsafe { kernel32::AddVectoredExceptionHandler(0, Some(ExceptionHandler)) };

        // XXX: This causes mpengine to throw an exception and be very unhappy
        // unsafe { kernel32::FreeLibrary(self.DllModule) };
    }
}

pub fn read_scan_response(hRead: HANDLE) -> Option<ScanReplyMsg> {
    let mut bytes_read: DWORD = 0 as DWORD;
    let mut size: DWORD = 0 as DWORD;

    if unsafe {
           kernel32::ReadFile(hRead,
                              mem::transmute::<&mut DWORD, LPVOID>(&mut size),
                              mem::size_of::<DWORD>() as DWORD,
                              &mut bytes_read,
                              null_mut())
       } == 0 {
        return None;
    }

    if bytes_read != mem::size_of::<DWORD>() as DWORD {
        return None;
    }

    let mut raw_buf: Vec<u8> = Vec::with_capacity(size as usize);
    let buf_ptr = raw_buf.as_mut_ptr();

    if unsafe {
           kernel32::ReadFile(hRead,
                              mem::transmute::<*mut u8, LPVOID>(buf_ptr),
                              size,
                              &mut bytes_read,
                              null_mut())
       } == 0 {
        return None;
    }

    if bytes_read != size {
        return None;
    }

    mem::forget(raw_buf);
    let buf = unsafe { Vec::from_raw_parts(buf_ptr, size as usize, size as usize) };
    let serialized = match String::from_utf8(buf) {
        Ok(x) => x,
        Err(_) => return None,
    };

    let deserialized: ScanReplyMsg = match serde_json::from_str(&serialized) {
        Ok(x) => x,
        Err(_) => return None,
    };

    Some(deserialized)
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

#[test]
fn test_init_mpengine() {
    let support_path = get_support_path().unwrap();

    let mut mpengine_path = support_path.clone();
    mpengine_path.push("mpengine.dll");
    assert!(mpengine_path.exists());

    let mut eicar_path = get_unittest_support_path().unwrap();
    eicar_path.push("eicar.com");
    assert!(eicar_path.exists());

    let engine_result = MpEngine::load(mpengine_path.to_str().unwrap());
    assert!(engine_result.is_some());

    let mut engine = engine_result.unwrap();

    let wPath: Vec<u16> = OsStr::new(eicar_path.to_str().unwrap())
        .encode_wide()
        .chain(once(0))
        .collect();

    let mut hReadPipe: HANDLE = INVALID_HANDLE_VALUE;
    let mut hWritePipe: HANDLE = INVALID_HANDLE_VALUE;

    assert!(unsafe { kernel32::CreatePipe(&mut hReadPipe, &mut hWritePipe, null_mut(), 0) } != 0);

    let ptr = USERPTR_HANDLES {
        hRead: unsafe {
            kernel32::CreateFileW(wPath.as_ptr(),
                                  GENERIC_READ,
                                  FILE_SHARE_READ,
                                  null_mut(),
                                  OPEN_EXISTING,
                                  FILE_ATTRIBUTE_NORMAL,
                                  null_mut())
        },
        hWrite: hWritePipe,
    };
    assert!(ptr.hRead != INVALID_HANDLE_VALUE);
    assert!(engine.scan(&ptr));

    assert!(read_scan_response(hReadPipe).is_some());
    let obj = match read_scan_response(hReadPipe) {
        Some(x) => x,
        None => {
            assert!(false);
            return;
        }
    };

    assert!((obj.Flags & 0x08000022) != 0);
    assert_eq!(obj.VirusName, "Virus:DOS/EICAR_Test_File");
}