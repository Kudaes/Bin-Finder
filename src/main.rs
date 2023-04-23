#[macro_use]
extern crate litcrypt;
use_litcrypt!();

use std::mem::size_of;
use std::{ptr, env};
use std::{collections::BTreeSet, iter::FromIterator};

use bindings::Windows::Win32::System::WindowsProgramming::IO_STATUS_BLOCK;
use bindings::Windows::Win32::{Foundation::{HANDLE}};
use data::{PVOID, FILE_PROCESS_IDS_USING_FILE_INFORMATION};

fn main() {
    unsafe
    {

        let args: Vec<String> = env::args().collect();

        if args.len() < 2 || args[1] == "-h" || args[1] == "--help"
        {
            print_help();
            return;
        } 

        let image = &args[1];
        
        let f: data::EnumProcesses;
        let ret: Option<bool>;
        let k32 = dinvoke::get_module_base_address(&lc!("kernelbase.dll"));
        let pids: Vec<u32> = vec![0;500];
        let mut pids: *mut u32 = pids.as_ptr() as *mut _;
        let needed = 0u32;
        let needed: *mut u32 = std::mem::transmute(&needed);
        dinvoke::dynamic_invoke!(k32,&lc!("EnumProcesses"),f,ret,pids,500*4,needed);

        match ret{
            Some(_x) => {}
            None => {println!("[x] EnumProcesses failed!"); return;}
        }

        let mut all: Vec<u32> = vec![0;500];
        for _i in 0..500
        {
            all.push(*pids);
            pids = pids.add(1);
        }

        let unwanted = get_pid_from_image_path(image);
        let unwanted = unwanted.to_vec();

        let unwanted:Vec<u32> = unwanted.into_iter().map(|x|x as u32).collect();
        let final_pids = remove_pids(all,unwanted);
        for pid in final_pids
        {
            let phand = dinvoke::open_process(0x1000, 0, pid);
            if phand.0 != 0 && phand.0 != -1
            {
                let path: Vec<u16> = vec![0; 260];
                let path: *mut u16 = path .as_ptr() as *mut _;
                let func: data::GetModuleFileNameExW;
                let ret: Option<u32>;
                dinvoke::dynamic_invoke!(k32,&lc!("GetModuleFileNameExW"),func,ret,phand,0,path,260);
                if ret.unwrap() != 0 
                {
                    let mut path: *mut u8 = path as *mut _;
                    print!("[+] ");
                    for _i in 0..ret.unwrap()
                    {
                        print!("{}",*path as char);
                        path = path.add(2);
                    }
                    print!(" - PID: {}", pid);
                    println!();
                }
            }
            else 
            {
                println!("[+] Process with PID {}", pid);
            }
        }   
    }   

}

// From https://stackoverflow.com/questions/64019451/how-do-i-remove-the-elements-of-vector-that-occur-in-another-vector-in-rust
fn remove_pids(mut items: Vec<u32>, to_remove: Vec<u32>) -> Vec<u32>
{
    let to_remove = BTreeSet::from_iter(to_remove);

    items.retain(|e| !to_remove.contains(e));

    items.to_vec()
}

pub fn get_pid_from_image_path(path: &str) -> [usize;500]
{
    unsafe
    {
        let mut file: Vec<u16> = path.encode_utf16().collect();
        file.push(0);
        let k32 = dinvoke::get_module_base_address("kernel32.dll");
        let create_file: data::CreateFile;
        let create_file_r: Option<HANDLE>;
        // 0x80 = FILE_READ_ATTRIBUTES
        // 3 = OPEN_EXISTING
        // 0x00000001|0x00000002|0x00000004 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
        dinvoke::dynamic_invoke!(k32,"CreateFileW",create_file,create_file_r,file.as_ptr() as *const u16,0x80,0x00000001|0x00000002|0x00000004,ptr::null(),
                                3,0,HANDLE {0: 0});
        
        let file_handle = create_file_r.unwrap();
        
        if file_handle.0 == -1
        {
            return [0;500];
        }

        let fpi: *mut FILE_PROCESS_IDS_USING_FILE_INFORMATION;
        let ios: Vec<u8> = vec![0u8; size_of::<IO_STATUS_BLOCK>()];
        let iosb: *mut IO_STATUS_BLOCK = std::mem::transmute(&ios);
        let mut ptr: PVOID;
        let mut buffer;
        let mut bytes = size_of::<FILE_PROCESS_IDS_USING_FILE_INFORMATION>() as u32;
        let mut c = 0;
        loop
        { 
            buffer =  vec![0u8; bytes as usize];
            ptr = std::mem::transmute(buffer.as_ptr());
            // 47 = FileProcessIdsUsingFileInformation
            let x = dinvoke::nt_query_information_file(file_handle, iosb,ptr,bytes,47);

            if x != 0 
            {
                bytes *= 2;
            }
            else
            {
                fpi = std::mem::transmute(ptr);
                let _r = dinvoke::close_handle(file_handle);
                // Access denied error is thrown if this pointer is not liberated.
                (*iosb).Anonymous.Pointer = ptr::null_mut();
                return (*fpi).process_id_list;
            }

            c = c + 1;

            if c > 20
            {
                println!("{}", "[x] Timeout. Call to NtQueryInformationFile failed.");
                break;
            }
        } 

        let _r = dinvoke::close_handle(file_handle);

        [0;500]
    }
}

fn print_help() {
    
    let help = lc!("
    USAGE:
        check.exe [OPTIONS] <dll>
    ARGS:
        <dll>                       Dll to look for.
    OPTIONS:
        -h, --help                  Print help information.
    ");
    
        println!("{}", help);
}