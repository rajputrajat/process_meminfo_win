use log::info;
use std::mem;
use windows::Win32::{
    Foundation::{GetLastError, WIN32_ERROR},
    System::ProcessStatus::K32EnumProcesses,
};

fn read_process_memory() {}

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
    Other(String),
}

impl From<WIN32_ERROR> for CustomError {
    fn from(e: WIN32_ERROR) -> Self {
        CustomError::Win32(e)
    }
}
