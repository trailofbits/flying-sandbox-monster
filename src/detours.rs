#![allow(non_camel_case_types)]

extern crate winapi;
extern crate kernel32;
extern crate field_offset;

use winapi::*;

#[allow(unused_imports)]
use self::field_offset::*;

use std::mem;
use std::ffi::CStr;
use std::ptr::null_mut;
use std::iter::once;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

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

DEF_STRUCT!{struct IMAGE_DOS_HEADER {
  e_magic: WORD,
  e_cblp: WORD,
  e_cp: WORD,
  e_crlc: WORD,
  e_cparhdr: WORD,
  e_minalloc: WORD,
  e_maxalloc: WORD,
  e_ss: WORD,
  e_sp: WORD,
  e_csum: WORD,
  e_ip: WORD,
  e_cs: WORD,
  e_lfarlc: WORD,
  e_ovno: WORD,
  e_res: [WORD; 4],
  e_oemid: WORD,
  e_oeminfo: WORD,
  e_res2: [WORD; 10],
  e_lfanew: LONG,
}}
pub type PIMAGE_DOS_HEADER = *mut IMAGE_DOS_HEADER;

DEF_STRUCT!{struct IMAGE_IMPORT_DESCRIPTOR {
    OriginalFirstThunk: DWORD,
    TimeDateStamp: DWORD,
    ForwarderChain: DWORD,
    Name: DWORD,
    FirstThunk: DWORD,
}}
pub type PIMAGE_IMPORT_DESCRIPTOR = *mut IMAGE_IMPORT_DESCRIPTOR;

DEF_STRUCT!{struct IMAGE_THUNK_DATA32 {
    u1: DWORD,
}}
pub type PIMAGE_THUNK_DATA32 = *mut IMAGE_THUNK_DATA32;

DEF_STRUCT!{struct IMAGE_IMPORT_BY_NAME {
    Hint: WORD,
    Name: BYTE,
}}
pub type PIMAGE_IMPORT_BY_NAME = *mut IMAGE_IMPORT_BY_NAME;

const IMAGE_DOS_SIGNATURE: WORD = 0x5a4d;
const IMAGE_NT_SIGNATURE: DWORD = 0x4550;

const IMAGE_ORDINAL_FLAG: DWORD = 0x80000000;

struct MemoryWriteLock {
    addr: LPVOID,
    size: SIZE_T,
    old_protect: DWORD,
}

impl MemoryWriteLock {
    pub fn new(addr: LPVOID, size: SIZE_T) -> Option<MemoryWriteLock> {
        let mut lock = MemoryWriteLock {
            addr: addr,
            size: size,
            old_protect: 0 as DWORD,
        };

        if unsafe {
               kernel32::VirtualProtect(addr, size, PAGE_READWRITE, &mut lock.old_protect)
           } == 0 {
            return None;
        }

        Some(lock)
    }
}

impl Drop for MemoryWriteLock {
    fn drop(&mut self) {
        let mut old_protect: DWORD = 0 as DWORD;
        unsafe {
            kernel32::VirtualProtect(self.addr, self.size, self.old_protect, &mut old_protect)
        };
    }
}

#[cfg(test)]
fn assert_mem_protect(addr: LPVOID, size: SIZE_T, protect: DWORD) {
    let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { mem::zeroed() };

    assert!(unsafe { kernel32::VirtualQuery(addr, &mut mbi, size) } != 0);
    assert_eq!(mbi.Protect, protect);
}

#[test]
fn test_memorywritelock() {
    let size = 0x1000;
    let addr = unsafe { kernel32::VirtualAlloc(null_mut(), size, MEM_COMMIT, PAGE_READONLY) };
    assert!(addr != 0 as LPVOID);

    assert_mem_protect(addr, size, PAGE_READONLY);

    {
        let lock = MemoryWriteLock::new(addr, size);
        assert!(lock.is_some());

        assert_mem_protect(addr, size, PAGE_READWRITE);
    }

    assert_mem_protect(addr, size, PAGE_READONLY);
}

pub struct Module {
    module: HMODULE,
}

impl Module {
    #[allow(dead_code)]
    pub fn target(moduleName: &str) -> Option<Module> {
        let mut library = Module { module: 0 as HMODULE };

        let wModuleName: Vec<u16> = OsStr::new(moduleName)
            .encode_wide()
            .chain(once(0))
            .collect();

        library.module = unsafe { kernel32::GetModuleHandleW(wModuleName.as_ptr()) };
        if library.module == 0 as HMODULE {
            return None;
        }

        Some(library)
    }

    pub fn self_target() -> Module {
        Module { module: unsafe { kernel32::GetModuleHandleW(null_mut()) } }
    }

    pub fn intercept(&self,
                     targetModule: &str,
                     funcName: &str,
                     replaceFuncPtr: LPVOID)
                     -> Option<LPVOID> {
        let base_addr: PBYTE = unsafe { mem::transmute::<HMODULE, PBYTE>(self.module) };
        let dos_hdr: PIMAGE_DOS_HEADER =
            unsafe { mem::transmute::<HMODULE, PIMAGE_DOS_HEADER>(self.module) };

        if unsafe { (*dos_hdr).e_magic } != IMAGE_DOS_SIGNATURE {
            return None;
        }

        let nt_hdr: PIMAGE_NT_HEADERS32 =
            unsafe {
                mem::transmute::<PBYTE, PIMAGE_NT_HEADERS32>(base_addr.offset((*dos_hdr).e_lfanew as
                                                                              isize))
            };

        if unsafe { (*nt_hdr).Signature } != IMAGE_NT_SIGNATURE {
            return None;
        }

        if unsafe { (*nt_hdr).FileHeader.Machine } != IMAGE_FILE_MACHINE_I386 {
            // TODO: Think about adding support for IMAGE_FILE_MACHINE_AMD64 later
            return None;
        }

        let import_desc_array: PIMAGE_IMPORT_DESCRIPTOR = unsafe {
            mem::transmute::<PBYTE, PIMAGE_IMPORT_DESCRIPTOR>(
                base_addr.offset((*nt_hdr).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize].VirtualAddress as isize)
            )
        };

        let mut i = 0;
        loop {
            let import_desc = unsafe { (*import_desc_array.offset(i)) };
            if import_desc.OriginalFirstThunk == 0 {
                break;
            }

            let dll_name =
                unsafe { CStr::from_ptr(base_addr.offset(import_desc.Name as isize) as *const i8) }
                    .to_string_lossy();

            if targetModule.to_string().to_lowercase() == dll_name.to_lowercase() {
                if import_desc.FirstThunk == 0 || import_desc.OriginalFirstThunk == 0 {
                    return None;
                }

                let thunk_ptr: PIMAGE_THUNK_DATA32 =
                    unsafe {
                        mem::transmute::<PBYTE,
                                         PIMAGE_THUNK_DATA32>(base_addr
                                                                  .offset(import_desc.FirstThunk as
                                                                          isize))
                    };
                let orig_thunk_ptr: PIMAGE_THUNK_DATA32 =
                    unsafe {
                        mem::transmute::<PBYTE, 
                                         PIMAGE_THUNK_DATA32>(base_addr
                                                                  .offset(import_desc.OriginalFirstThunk as
                                                                          isize))
                    };

                let mut j = 0;
                loop {
                    let orig_thunk = unsafe { *orig_thunk_ptr.offset(j) };

                    if orig_thunk.u1 == 0 {
                        break;
                    }

                    if (orig_thunk.u1 & IMAGE_ORDINAL_FLAG) != 0 {
                        continue;
                    }

                    let import: PIMAGE_IMPORT_BY_NAME =
                        unsafe {
                            mem::transmute::<PBYTE,
                                             PIMAGE_IMPORT_BY_NAME>(base_addr
                                                                        .offset(orig_thunk.u1 as
                                                                                isize))
                        };
                    let name_field = offset_of!(IMAGE_IMPORT_BY_NAME => Name);
                    let func_name =
                        unsafe { CStr::from_ptr(name_field.apply_ptr(import) as *const i8) }
                            .to_string_lossy();

                    if funcName == func_name {
                        let old_func_ptr: LONG;
                        let iat_ptr_field = offset_of!(IMAGE_THUNK_DATA32 => u1);
                        {
                            #[allow(unused_variables)]
                            let lock =
                                MemoryWriteLock::new(iat_ptr_field.apply_ptr(unsafe { thunk_ptr.offset(j) }) as
                                                     LPVOID,
                                                     mem::size_of::<LPVOID>() as u32);
                            old_func_ptr = unsafe {
                                kernel32::InterlockedExchange(
                                    iat_ptr_field.apply_ptr_mut(thunk_ptr.offset(j)) as *mut LONG,
                                    replaceFuncPtr as LONG)
                            };
                        }

                        return Some(old_func_ptr as LPVOID);
                    }

                    j += 1;
                }
            }

            i += 1;
        }

        None
    }
}

#[allow(unused_variables)]
#[cfg(test)]
extern "system" fn myCreatePipe(hReadPipe: PHANDLE,
                                hWritePipe: PHANDLE,
                                lpPipeAttributes: LPVOID,
                                nSize: DWORD)
                                -> BOOL {
    0x31337
}

#[test]
fn test_intercept() {
    let target = Module::self_target();

    let mut result = target.intercept("kernel32.dll", "CreatePipe", unsafe {
        mem::transmute::<extern "system" fn(PHANDLE,
                                            PHANDLE,
                                            LPVOID,
                                            DWORD)
                                            -> BOOL,
                         LPVOID>(myCreatePipe)
    });
    assert!(result.is_some());

    let ret = unsafe { kernel32::CreatePipe(null_mut(), null_mut(), null_mut(), 0x1337) };
    assert_eq!(ret, 0x31337);

    result = target.intercept("kernel32.dll", "CreatePipe", result.unwrap());
    assert!(result.is_some());
}