use log::info;
use std::{mem, string::FromUtf16Error};
pub use windows::Win32::System::ProcessStatus::PROCESS_MEMORY_COUNTERS;
use windows::{
    core::Error as WinCoreError,
    Win32::{
        Foundation::{GetLastError, HANDLE, HINSTANCE, PWSTR, WIN32_ERROR},
        System::{
            ProcessStatus::{
                K32EnumProcessModulesEx, K32EnumProcesses, K32GetModuleBaseNameW,
                K32GetProcessMemoryInfo, LIST_MODULES_ALL,
            },
            Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ},
        },
    },
};

pub fn read_process_memory(handle: &HANDLE) -> Result<PROCESS_MEMORY_COUNTERS, CustomError> {
    let mut mem_counters = PROCESS_MEMORY_COUNTERS::default();
    if unsafe {
        K32GetProcessMemoryInfo(
            handle,
            &mut mem_counters,
            mem::size_of_val(&mem_counters) as u32,
        )
    }
    .as_bool()
    {
        Ok(mem_counters)
    } else {
        Err(get_last_error())
    }
}

pub fn get_process_name(handle: &HANDLE) -> Result<String, CustomError> {
    let mut hmodule = HINSTANCE::default();
    let mut bytes_needed: u32 = 0;
    if unsafe {
        K32EnumProcessModulesEx(
            handle,
            &mut hmodule,
            mem::size_of_val(&hmodule) as u32,
            &mut bytes_needed,
            LIST_MODULES_ALL,
        )
    }
    .as_bool()
    {
        let mut wstr_buffer: [u16; 256] = [0; 256];
        let base_name = PWSTR(wstr_buffer.as_mut_ptr());
        unsafe { K32GetModuleBaseNameW(handle, hmodule, base_name, wstr_buffer.len() as u32) };
        Ok(String::from_utf16(&wstr_buffer)?)
    } else {
        Err(get_last_error())
    }
}

pub fn get_process_handle(pid: ProcessId) -> Result<HANDLE, CustomError> {
    let handle =
        unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) }.ok()?;
    Ok(handle)
}

pub type ProcessId = u32;

#[derive(Debug)]
pub struct ProcessIds(pub Vec<u32>);

pub fn enum_processes() -> Result<ProcessIds, CustomError> {
    let mut num_processes_requested = 512;
    loop {
        let mut pid_processes: Vec<u32> = vec![0; num_processes_requested];
        let mut bytes_returned_in_process_array: u32 = 0;
        let return_status = unsafe {
            K32EnumProcesses(
                pid_processes.as_mut_ptr() as *mut u32,
                (pid_processes.len() * mem::size_of::<u32>()) as u32,
                &mut bytes_returned_in_process_array,
            )
        }
        .as_bool();
        info!("number of read bytes: {bytes_returned_in_process_array}");
        if return_status {
            let num_read_processes =
                bytes_returned_in_process_array as usize / mem::size_of::<u32>();
            if pid_processes.len() > num_read_processes {
                return Ok(ProcessIds(pid_processes[..num_read_processes].to_vec()));
            } else {
                num_processes_requested *= 2;
                continue;
            }
        } else {
            return Err(get_last_error());
        }
    }
}

pub fn get_last_error() -> CustomError {
    CustomError::from(unsafe { GetLastError() })
}

#[derive(Debug)]
pub enum CustomError {
    Win32(WIN32_ERROR),
    Utf16(FromUtf16Error),
    WinCore(WinCoreError),
    Other(String),
}

impl From<WIN32_ERROR> for CustomError {
    fn from(e: WIN32_ERROR) -> Self {
        CustomError::Win32(e)
    }
}

impl From<FromUtf16Error> for CustomError {
    fn from(e: FromUtf16Error) -> Self {
        CustomError::Utf16(e)
    }
}

impl From<WinCoreError> for CustomError {
    fn from(e: WinCoreError) -> Self {
        CustomError::WinCore(e)
    }
}
