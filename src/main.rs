use walkdir::WalkDir;
use std::{env, ptr};
use std::ffi::c_void;
use std::mem;
use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::{HANDLE, HWND};
use windows::Win32::Security::WinTrust::*;

extern crate windows;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() == 1 {
        println!("Usage: {} <root dir>", &args[0]);
        return;
    }
    unsafe {
        walk_path(args);
    }
}

unsafe fn walk_path(args: Vec<String>) {
    let root_dir = &args[1];

    for entry in WalkDir::new(root_dir) {
        match entry {
            Ok(entry) => {
                let path = entry.path().to_str().unwrap();
                if str::ends_with(&path, ".dll") {
                    process_file(path);
                }
            }
            Err(_entry) => {
                continue;
            }
        }
    }
}

unsafe fn process_file(path: &str) {

    let mut file_data = WINTRUST_FILE_INFO {
        hFile: HANDLE::default() as HANDLE,
        pcwszFilePath: PCWSTR(path.as_ptr() as *mut _),
        pgKnownSubject: 0 as *mut GUID,
        cbStruct: (mem::size_of::<&WINTRUST_FILE_INFO> as u32),
    };

    let wintrust_data_0 = WINTRUST_DATA_0 {
        pFile: &mut file_data
    };

    let mut wintrust_data = WINTRUST_DATA::default();
    wintrust_data.cbStruct = mem::size_of::<WINTRUST_DATA> as u32;
    wintrust_data.pPolicyCallbackData = ptr::null_mut();
    wintrust_data.pSIPClientData = ptr::null_mut();
    wintrust_data.dwUIChoice = WTD_UI_NONE;
    wintrust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
    wintrust_data.dwUnionChoice = WTD_CHOICE_FILE;
    wintrust_data.Anonymous = wintrust_data_0;
    wintrust_data.dwStateAction = WTD_STATEACTION_VERIFY;
    wintrust_data.hWVTStateData = HANDLE::default();
    wintrust_data.pwszURLReference = PWSTR::null();
    wintrust_data.dwUIContext = WINTRUST_DATA_UICONTEXT::default();

    let mut wintrust_action_generic_verify_v2 = GUID::from_values(0xaac56b, 0xcd44, 0x11d0, [0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee]);
    let state_ptr: *mut c_void = &mut wintrust_data as *mut _ as *mut c_void;
    let status = WinVerifyTrust(HWND::default(), &mut wintrust_action_generic_verify_v2, state_ptr);

    match status {
        0 => (),
        _ => println!("Unsigned DLL found: {}", &path),
    }

    wintrust_data.dwStateAction = WTD_STATEACTION_CLOSE;

    WinVerifyTrust(HWND::default(), &mut wintrust_action_generic_verify_v2, state_ptr);
}
