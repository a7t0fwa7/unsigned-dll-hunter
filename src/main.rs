use walkdir::WalkDir;
use std::{env, ptr};
use std::ffi::c_void;
use std::mem;
use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::{HANDLE, HWND};
use windows::Win32::Security::WinTrust::{WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_DATA_UICONTEXT,
                                         WINTRUST_FILE_INFO, WinVerifyTrust, WTD_CHOICE_FILE,
                                         WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE,
                                         WTD_STATEACTION_VERIFY, WTD_UI_NONE};

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
    println!("Walking {}...", root_dir);

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
        pcwszFilePath: PCWSTR::from_raw(path.encode_utf16().collect::<Vec<u16>>().as_mut_ptr()),
        pgKnownSubject: 0 as *mut GUID,
        cbStruct: (mem::size_of::<WINTRUST_FILE_INFO> as u32),
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

    const TRUST_E_SYSTEM_ERROR: u32 = 0x80096001;
    const TRUST_E_NO_SIGNER_CERT: u32 = 0x80096002;
    const TRUST_E_COUNTER_SIGNER: u32 = 0x80096003;
    const TRUST_E_CERT_SIGNATURE: u32 = 0x80096004;
    const TRUST_E_TIME_STAMP: u32 = 0x80096005;
    const TRUST_E_BAD_DIGEST: u32 = 0x80096010;
    const TRUST_E_BASIC_CONSTRAINTS: u32 = 0x80096019;
    const TRUST_E_FINANCIAL_CRITERIA: u32 = 0x8009601E;
    const TRUST_E_PROVIDER_UNKNOWN: u32 = 0x800B0001;
    const TRUST_E_ACTION_UNKNOWN: u32 = 0x800B0002;
    const TRUST_E_SUBJECT_FORM_UNKNOWN: u32 = 0x800B0003;
    const TRUST_E_SUBJECT_NOT_TRUSTED: u32 = 0x800B0004;
    const TRUST_E_NOSIGNATURE: u32 = 0x800B0100;
    const CERT_E_UNTRUSTEDROOT: u32 = 0x800B0109;
    const TRUST_E_FAIL: u32 = 0x800B010B;
    const TRUST_E_EXPLICIT_DISTRUST: u32 = 0x800B0111;
    const CERT_E_CHAINING: u32 = 0x800B010A;
    const CRYPT_E_FILE_ERROR: u32 = 0x80092003;

    match status as u32{
        0 => (),
        TRUST_E_SYSTEM_ERROR => println!("Unsigned DLL found: {} - result TRUST_E_SYSTEM_ERROR", &path),
        TRUST_E_NO_SIGNER_CERT => println!("Unsigned DLL found: {} - result TRUST_E_NO_SIGNER_CERT", &path),
        TRUST_E_COUNTER_SIGNER => println!("Unsigned DLL found: {} - result TRUST_E_COUNTER_SIGNER", &path),
        TRUST_E_CERT_SIGNATURE => println!("Unsigned DLL found: {} - result TRUST_E_CERT_SIGNATURE", &path),
        TRUST_E_TIME_STAMP => println!("Unsigned DLL found: {} - result TRUST_E_TIME_STAMP", &path),
        TRUST_E_BAD_DIGEST => println!("Unsigned DLL found: {} - result TRUST_E_BAD_DIGEST", &path),
        TRUST_E_BASIC_CONSTRAINTS => println!("Unsigned DLL found: {} - result TRUST_E_BASIC_CONSTRAINTS", &path),
        TRUST_E_FINANCIAL_CRITERIA => println!("Unsigned DLL found: {} - result TRUST_E_FINANCIAL_CRITERIA", &path),
        TRUST_E_PROVIDER_UNKNOWN => println!("Unsigned DLL found: {} - result TRUST_E_PROVIDER_UNKNOWN", &path),
        TRUST_E_ACTION_UNKNOWN => println!("Unsigned DLL found: {} - result TRUST_E_ACTION_UNKNOWN", &path),
        TRUST_E_SUBJECT_FORM_UNKNOWN => println!("Unsigned DLL found: {} - result TRUST_E_SUBJECT_FORM_UNKNOWN", &path),
        TRUST_E_SUBJECT_NOT_TRUSTED => println!("Unsigned DLL found: {} - result TRUST_E_SUBJECT_NOT_TRUSTED", &path),
        TRUST_E_NOSIGNATURE => println!("Unsigned DLL found: {} - result TRUST_E_NOSIGNATURE", &path),
        CERT_E_UNTRUSTEDROOT => println!("Unsigned DLL found: {} - result CERT_E_UNTRUSTEDROOT", &path),
        TRUST_E_FAIL => println!("Unsigned DLL found: {} - result TRUST_E_FAIL", &path),
        TRUST_E_EXPLICIT_DISTRUST => println!("Unsigned DLL found: {} - result TRUST_E_EXPLICIT_DISTRUST", &path),
        CERT_E_CHAINING => println!("Unsigned DLL found: {} - result CERT_E_CHAINING", &path),
        CRYPT_E_FILE_ERROR => (), //println!("Error: {}: CRYPT_E_FILE_ERROR", &path),
        _ => println!("Unknown error: {} - code: 0x{:X}", &path, status),
    }

    wintrust_data.dwStateAction = WTD_STATEACTION_CLOSE;

    WinVerifyTrust(HWND::default(), &mut wintrust_action_generic_verify_v2, state_ptr);
}
