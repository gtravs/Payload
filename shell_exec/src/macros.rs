use core::ffi::c_void;
use winapi::shared::minwindef::BOOL;
use winapi::um::minwinbase::SECURITY_ATTRIBUTES;
use winapi::um::processthreadsapi::{PROCESS_INFORMATION, STARTUPINFOA, STARTUPINFOW};
use winapi::um::winnt::{HANDLE, PCSTR, PCWSTR, PSTR, PWSTR};
use crate::pe::{OVERLAPPED};

pub type HANDLE_FLAGS = u32;
pub type WAIT_EVENT = u32;
pub type PROCESS_CREATION_FLAGS = u32;

pub const  KERNEL32_HASH:u32  = 0x6DDB9555;
pub const  NTDLL_HASH:u32 = 0x1EDAB0ED;
pub const  NTALLOCATEVIRTUALMEMORY_HASH :u32 = 0xF783B8EC;
pub const  CREATEPROCESSW_HASH :u32 = 0xFBAF90CF;
pub type FnCreateProcessW = unsafe extern "system" fn(
    lpapplicationname: PCWSTR,
    lpcommandline: PWSTR,
    lpprocessattributes: *const SECURITY_ATTRIBUTES,
    lpthreadattributes: *const SECURITY_ATTRIBUTES,
    binherithandles: BOOL,
    dwcreationflags: PROCESS_CREATION_FLAGS,
    lpenvironment: *const c_void,
    lpcurrentdirectory: PCWSTR,
    lpstartupinfo: *const STARTUPINFOW,
    lpprocessinformation: *mut PROCESS_INFORMATION,
) -> BOOL;
pub const  WRITEFILE_HASH : u32 = 0xF1D207D0;
pub type FnWriteFile = unsafe extern "system" fn(
    hfile: HANDLE,
    lpbuffer: *const u8,
    nnumberofbytestowrite: u32,
    lpnumberofbyteswritten: *mut u32,
    lpoverlapped: *mut OVERLAPPED,
) -> BOOL;
pub const READFILE_HASH:u32 = 0x84D15061;
pub type  FnReadFile =  unsafe extern "system" fn(
    hfile: HANDLE,
    lpbuffer: *mut u8,
    nnumberofbytestoread: u32,
    lpnumberofbytesread: *mut u32,
    lpoverlapped: *mut OVERLAPPED,
) -> BOOL;
pub const CREATEPIPE_HASH:u32 = 0x9694E9E7;
pub type FnCreatePipe = unsafe extern "system" fn(
    hreadpipe: *mut HANDLE,
    hwritepipe: *mut HANDLE,
    lppipeattributes: *const SECURITY_ATTRIBUTES,
    nsize: u32,
) -> BOOL;
pub const SETHANDLEINFORMATION_HASH:u32 = 0xAB95E7E3;
pub type FnSetHandleInformation = unsafe extern "system" fn(
    hobject: HANDLE,
    dwmask: u32,
    dwflags: HANDLE_FLAGS,
) -> BOOL;
pub const CLOSEHANDLE_HASH:u32 = 0xFDB928E7;
pub type  FnCloseHandle = unsafe extern "system" fn(hobject: HANDLE) -> BOOL;
pub const GETEXITCODEPROCESS_HASH:u32 = 0xA7C5FD39;
pub type FnGetExitCodeProcess = unsafe extern "system" fn(
    hprocess: HANDLE,
    lpexitcode: *mut u32,
) -> BOOL;
pub const WAITFORSINGLEOBJECT_HASH:u32 = 0x0DF1B3DA;
pub type FnWaitForSingleObject =  unsafe extern "system" fn (
    hhandle: HANDLE,
    dwmilliseconds: u32,
) -> WAIT_EVENT;

pub const CREATEFILEW_HASH:u32 = 0x687D2110;
pub type FILE_CREATION_DISPOSITION = u32;
pub type FILE_FLAGS_AND_ATTRIBUTES = u32;
pub type FILE_SHARE_MODE = u32;
pub type  FnCreateFileW =  unsafe extern "system" fn(
    lpfilename: PCWSTR,
    dwdesiredaccess: u32,
    dwsharemode: FILE_SHARE_MODE,
    lpsecurityattributes: *const SECURITY_ATTRIBUTES,
    dwcreationdisposition: FILE_CREATION_DISPOSITION,
    dwflagsandattributes: FILE_FLAGS_AND_ATTRIBUTES,
    htemplatefile: HANDLE,
) -> HANDLE;

pub const CREATEFILEA_HASH:u32 = 0x687D20FA;
pub type  FnCreateFileA = unsafe extern "system" fn(
    lpfilename: PCSTR,
    dwdesiredaccess: u32,
    dwsharemode: FILE_SHARE_MODE,
    lpsecurityattributes: *const SECURITY_ATTRIBUTES,
    dwcreationdisposition: FILE_CREATION_DISPOSITION,
    dwflagsandattributes: FILE_FLAGS_AND_ATTRIBUTES,
    htemplatefile: HANDLE,
) -> HANDLE;



pub const CREATEPROCESSA_HASH:u32 = 0xFBAF90B9;
pub type FnCreateProcessA = unsafe extern "system" fn (
    lpapplicationname: PCSTR,
    lpcommandline: PSTR,
    lpprocessattributes: *const SECURITY_ATTRIBUTES,
    lpthreadattributes: *const SECURITY_ATTRIBUTES,
    binherithandles: BOOL,
    dwcreationflags: PROCESS_CREATION_FLAGS,
    lpenvironment: *const c_void,
    lpcurrentdirectory: PCSTR,
    lpstartupinfo: *const STARTUPINFOA,
    lpprocessinformation: *mut PROCESS_INFORMATION,
) -> BOOL;

pub const VIRTUALPROTECT_HASH:u32 = 0xE857500D;
pub type PAGE_PROTECTION_FLAGS = u32;
pub type  FnVirtualProtect =  unsafe extern "system" fn (
    lpaddress: *const c_void,
    dwsize: usize,
    flnewprotect: PAGE_PROTECTION_FLAGS,
    lpfloldprotect: *mut PAGE_PROTECTION_FLAGS,
) -> BOOL;

pub const GETLASTERROR_HASH:u32 = 0x8160BDC3;
pub type WIN32_ERROR = u32;
pub type FnGetLastError = unsafe extern "system" fn() -> WIN32_ERROR;