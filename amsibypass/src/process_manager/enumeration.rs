
use ntapi::ntexapi::*;
use ntapi::ntldr::LDR_DATA_TABLE_ENTRY;
use ntapi::ntpebteb::PEB;
use ntapi::ntpsapi::*;
use winapi::ctypes::*;
use winapi::um::processthreadsapi::*;
use winapi::um::handleapi::*;
use winapi::um::memoryapi::*;
use winapi::shared::ntdef::*;
use winapi::um::errhandlingapi::*;
use winapi::um::tlhelp32::*;
use winapi::um::synchapi::*;
use winapi::um::winnt::*;
use winapi::shared::winerror::*;
use crate::utils::parse_structure_from_memory;
use super::flags::SystemInformationClassFlags;
use std::collections::*;
use std::io::Read;
use ntapi::ntrtl::RTL_USER_PROCESS_PARAMETERS;

#[derive(Debug,Clone)]
pub struct Process{
    pid: u32,
    ppid: u32,
    name: String,
    path: String

}


#[derive(Debug,Clone)]
pub struct Processes{
    process_info: Vec<Process>
}


impl Process{


    fn get_ntquerysysteminformation(flag:SystemInformationClassFlags) -> Result<Vec<u8>,String>{
        let mut reqlength = 0;

        let mut i = 0;
        let p  = loop{
            let mut p = vec![0u8;reqlength as usize];

            let ntstatus = unsafe{NtQuerySystemInformation(flag.bits(),p.as_mut_ptr() as *mut c_void,p.len() as u32,&mut reqlength)};
            if NT_SUCCESS(ntstatus){
                break p;
            }
            if i==100{
                return Err(format!("NtQuerySystemInformation error occured: {}",ntstatus));
            }

            i+=1;

        };
        Ok(p)
    }

    pub fn get_process_info_by_id(pid: u32) ->Result<Self,String> {

        let p = Self::get_ntquerysysteminformation(SystemInformationClassFlags::SystemProcessInformation);
        if p.is_err(){
            return Err(p.err().unwrap());
        }

        let p = p.unwrap();

        let mut startingprocess = p.as_ptr() as usize;

        't:loop{

            let pi = unsafe{std::ptr::read(startingprocess as  *const SYSTEM_PROCESS_INFORMATION)};
            let nextentry = pi.NextEntryOffset;

            if nextentry==0{
                return Err(format!("No process with the process id {} found",pid));
            }

            let imagename = readunicodestringfrommemory(unsafe{GetCurrentProcess()},pi.ImageName.Buffer as *const c_void);

            if pi.UniqueProcessId as u32 == pid{
                return Ok(Process{
                    pid: pi.UniqueProcessId as u32,
                    ppid: 69,
                    name: imagename,
                    path: "to be found".to_owned()
                });
            }


            startingprocess += nextentry as usize;

        }

    }





    pub fn get_process_name<'l1>(&'l1 self) -> &String{
        &self.name
    }


    pub fn get_process_id(&self) -> u32{
        self.pid
    }

    pub fn get_parent_process_id(&self) -> Result<u32,String>{


        let snaphandle = unsafe{CreateToolhelp32Snapshot(0x2,0)};
        if snaphandle==INVALID_HANDLE_VALUE{
            return Err(format!("CreateToolhelp32Snapshot failed: {}",unsafe{GetLastError()}));
        }

        let mut pentry = unsafe{std::mem::zeroed::<PROCESSENTRY32W>()};
        pentry.dwSize = unsafe{std::mem::size_of_val(&pentry)} as u32;

        let res = unsafe{Process32FirstW(snaphandle,&mut pentry)} ;


        // 18 for ERROR_NO_MORE_FILES
        if res==0 || res==18{
            return Err(format!("Process32FirstW failed: {}",unsafe{GetLastError()}));
        }

        if pentry.th32ProcessID==self.pid{
            return Ok(pentry.th32ParentProcessID);
        }

        loop{
            pentry = unsafe{std::mem::zeroed::<PROCESSENTRY32W>()};
            pentry.dwSize = unsafe{std::mem::size_of_val(&pentry)} as u32;

            let res2 = unsafe{Process32NextW(snaphandle,&mut pentry)};

            if res2==0 || res2== 18{
                break;
            }

            if pentry.th32ProcessID==self.pid{
                return Ok(pentry.th32ParentProcessID);
            }


        }
        Err("something went wrong".to_string())
    }

    pub fn get_process_path<'l1>(&'l1 self) -> &String{
        &self.path
    }


    pub fn get_pebaddress(&self) -> Result<usize,String>{
        /*let snaphandle =  unsafe{CreateToolhelp32Snapshot(TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32,0)};
         if snaphandle == INVALID_HANDLE_VALUE{
             // return Err(format!("createtoolhelp32snapshot failed: {}",unsafe{GetLastError()}));
         }

         let mut mentry = unsafe{std::mem::zeroed::<MODULEENTRY32W>()};
         mentry.dwSize = std::mem::size_of_val(&mentry) as u32;

         let res = unsafe{Module32FirstW(snaphandle,&mut mentry)};
         if res==0 || res==18{
             // return Err(format!("Module32FirstW failed: {}",unsafe{GetLastError()}));
         }

         println!("pid: {}",mentry.th32ProcessID);
         let dllname = readunicodestringfrommemory(unsafe{GetCurrentProcess()},mentry.szModule.as_ptr() as *const c_void);
         println!("dllname: {}",dllname);


         'innerloop: loop {

             mentry = unsafe{std::mem::zeroed::<MODULEENTRY32W>()};
             mentry.dwSize = std::mem::size_of_val(&mentry) as u32;

             let res2 = unsafe{Module32NextW(snaphandle,&mut mentry)};

             if res2==0 || res2==18{
                 break 'innerloop;
             }


                 println!("pid: {}",mentry.th32ProcessID);
                 let dllname = readunicodestringfrommemory(unsafe{GetCurrentProcess()},mentry.szModule.as_ptr() as *const c_void);
                 println!("dllname: {}",dllname);




         }*/


        let prochandle = unsafe{OpenProcess(PROCESS_VM_READ|PROCESS_QUERY_INFORMATION,0,self.get_process_id() as u32)};
        if prochandle.is_null(){
            return Err(format!("openprocess failed: {}",unsafe{GetLastError()}));
        }

        let mut buffer = vec![0u8;std::mem::size_of::<PROCESS_BASIC_INFORMATION>()];

        let mut reqlength = 0;
        let ntstatus = unsafe{NtQueryInformationProcess(prochandle,0,
                                                        buffer.as_mut_ptr() as *mut c_void,buffer.len() as u32,&mut reqlength)};

        unsafe{CloseHandle(prochandle)};

        if NT_SUCCESS(ntstatus){
            let pbi = parse_structure_from_memory::<PROCESS_BASIC_INFORMATION>(unsafe{GetCurrentProcess()},buffer.as_ptr() as usize).unwrap();

            Ok(pbi.PebBaseAddress as usize)
        }

        else{
            Err(format!("unable to get peb addresss"))
        }

    }


    pub fn get_loaded_dlls(&self) -> Result<HashMap<String,usize>,String>{

        let res = self.get_pebaddress();
        if res.is_err(){
            return Err(res.err().unwrap());
        }

        let prochandle = unsafe{OpenProcess(PROCESS_VM_READ|PROCESS_QUERY_INFORMATION,0,self.get_process_id() as u32)};
        if !prochandle.is_null(){
            let peb = parse_structure_from_memory::<PEB>(prochandle,res.unwrap());
            if peb.is_err(){
                return Err(peb.err().unwrap());
            }
            let peb = peb.unwrap();

            let mut dlls: HashMap<String,usize> = HashMap::new();

            let ldrdata = parse_structure_from_memory::<PEB_LDR_DATA>(prochandle,peb.Ldr as usize).unwrap();

            let mut firstflink = ldrdata.InLoadOrderModuleList.Flink;


            loop{

                if firstflink as usize==(peb.Ldr as usize + 16){
                    break;
                }

                let ldrdatatable = parse_structure_from_memory::<LDR_DATA_TABLE_ENTRY>(prochandle,(firstflink) as usize).unwrap();

                let dllname = readunicodestringfrommemory(prochandle,ldrdatatable.FullDllName .Buffer as *const c_void);


                dlls.insert(dllname,ldrdatatable.DllBase as usize);
                firstflink = ldrdatatable.InLoadOrderLinks.Flink;


            }

            return Ok(dlls);
        }

        Err(format!("Opening handle to process failed"))
    }



    pub fn get_process_parameters(&self) -> Result<String,String> {
        let res = self.get_pebaddress();
        if res.is_err() {
            return Err(res.err().unwrap());
        }

        let prochandle = unsafe { OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 0, self.get_process_id() as u32) };
        if !prochandle.is_null() {
            let peb = parse_structure_from_memory::<PEB>(prochandle, res.unwrap());
            if peb.is_err() {
                return Err(peb.err().unwrap());
            }
            let peb = peb.unwrap();

            let rtlprocessparams = parse_structure_from_memory::<RTL_USER_PROCESS_PARAMETERS>(prochandle, peb.ProcessParameters as usize).unwrap();
            let cmdline = readunicodestringfrommemory(prochandle, rtlprocessparams.CommandLine.Buffer as *const c_void);



            return Ok(cmdline);
        }
        Err(format!("Something went wrong"))
    }


    pub fn set_process_parameters(&self,params:&str) -> Result<bool,String>{

        let res = self.get_pebaddress();
        if res.is_err() {
            return Err(res.err().unwrap());
        }

        let prochandle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, self.get_process_id() as u32) };
        if !prochandle.is_null() {
            let peb = parse_structure_from_memory::<PEB>(prochandle, res.unwrap());
            if peb.is_err() {
                return Err(peb.err().unwrap());
            }
            let peb = peb.unwrap();

            let rtlprocessparams = parse_structure_from_memory::<RTL_USER_PROCESS_PARAMETERS>(prochandle, peb.ProcessParameters as usize).unwrap();


            let mut paramsunicode = params.encode_utf16().collect::<Vec<u16>>();
            paramsunicode.push(0);
            paramsunicode.push(0);


            // writing unicode bytes
            let mut byteswritten = 0;
            unsafe{WriteProcessMemory(prochandle,
                                      rtlprocessparams.CommandLine.Buffer as *mut c_void,paramsunicode.as_ptr() as *const c_void,
                                      paramsunicode.len()*2,&mut byteswritten)};



            let cmdlineoffset = (&rtlprocessparams.CommandLine as *const _ as usize) - (&rtlprocessparams as *const _ as usize);

            // writing unicode_string's length
            unsafe{WriteProcessMemory(prochandle,
                                      (peb.ProcessParameters as usize+cmdlineoffset) as *mut c_void,
                                      (paramsunicode.len()*2).to_ne_bytes().as_ptr() as *const c_void,
                                      2,&mut byteswritten)};


            // writing unicode_string's Maxlength
            unsafe{WriteProcessMemory(prochandle,
                                      (peb.ProcessParameters as usize+cmdlineoffset+2) as *mut c_void,
                                      (paramsunicode.len()*2).to_ne_bytes().as_ptr() as *const c_void,
                                      2,&mut byteswritten)};


            let rtlprocessparams = parse_structure_from_memory::<RTL_USER_PROCESS_PARAMETERS>(prochandle, peb.ProcessParameters as usize).unwrap();

            //println!("cmdline buffer length: {}",rtlprocessparams.CommandLine.Length);
            //println!("cmdline buffer Maxlength: {}",rtlprocessparams.CommandLine.MaximumLength);

        }

        Ok(false)
    }


    pub fn get_environment_variables(&self) -> Result<Vec<String>,String>{
        let res = self.get_pebaddress();
        if res.is_err() {
            return Err(res.err().unwrap());
        }

        let prochandle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, self.get_process_id() as u32) };
        if !prochandle.is_null() {
            let peb = parse_structure_from_memory::<PEB>(prochandle, res.unwrap());
            if peb.is_err() {
                return Err(peb.err().unwrap());
            }
            let peb = peb.unwrap();

            let rtlprocessparams = parse_structure_from_memory::<RTL_USER_PROCESS_PARAMETERS>(prochandle, peb.ProcessParameters as usize).unwrap();

            let mut envvariables:Vec<String> = Vec::new();

            let mut t = 0;

            loop{


                if t>=rtlprocessparams.EnvironmentSize {
                    break;
                }

                let environ = readunicodestringfrommemory(prochandle,(rtlprocessparams.Environment as usize + t) as *const c_void);
                t += environ.len()*2+2;
                envvariables.push(environ);




            }






            return Ok(envvariables);
        }

        Err("something went wrong".to_string())
    }


    pub fn get_threadids(&self) -> Result<Vec<THREADENTRY32>,String>{

        let snaphandle= unsafe{CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0)};

        if snaphandle==INVALID_HANDLE_VALUE{
            return Err(format!("CreateToolhelp32Snapshot failed: {}",unsafe{GetLastError()}));
        }

        let mut threads:Vec<THREADENTRY32> = Vec::new();

        let mut tentry = unsafe{std::mem::zeroed::<THREADENTRY32>()};
        tentry.dwSize = unsafe{std::mem::size_of::<THREADENTRY32>()} as u32;

        let mut res = unsafe{Thread32First(snaphandle,&mut tentry)};




        loop{

            if res==0{
                break;
            }

            if tentry.th32OwnerProcessID==self.get_process_id(){

                threads.push(tentry.clone());
            }


            tentry = unsafe{std::mem::zeroed::<THREADENTRY32>()};
            tentry.dwSize = unsafe{std::mem::size_of::<THREADENTRY32>()} as u32;


            res = unsafe{Thread32Next(snaphandle,&mut tentry)};



        }






        Ok(threads)
    }





}


pub fn get_processes() -> Vec<Process>{

    let mut reqlength = 0;
    let p  = loop{
        let mut p = vec![0u8;reqlength as usize];

        let ntstatus = unsafe{NtQuerySystemInformation(5,p.as_mut_ptr() as *mut c_void,p.len() as u32,&mut reqlength)};
        if NT_SUCCESS(ntstatus){
            break p;
        }

    };

    let mut startingprocess = p.as_ptr() as usize;
    let mut processes: Vec<Process> = Vec::new();

    't:loop{

        let pi = unsafe{std::ptr::read(startingprocess as  *const SYSTEM_PROCESS_INFORMATION)};
        let nextentry = pi.NextEntryOffset;

        if nextentry==0{

            let imagename = readunicodestringfrommemory(unsafe{GetCurrentProcess()},pi.ImageName.Buffer as *const c_void).trim_end_matches('\0').to_string();

            processes.push(Process{
                pid: pi.UniqueProcessId as u32,
                ppid: 69,
                name: imagename,
                path: "to be found".to_owned()
            });
            break 't;
        }



        let imagename = readunicodestringfrommemory(unsafe{GetCurrentProcess()},pi.ImageName.Buffer as *const c_void).trim_end_matches('\0').to_string();


        processes.push(Process{
            pid: pi.UniqueProcessId as u32,
            ppid: 69,
            name: imagename,
            path: "to be found".to_owned()
        });

        startingprocess += nextentry as usize;

    }


    processes

}


pub fn get_process_info_by_name(pname: &str) -> Result<Process,String>{
    let processes = get_processes();
    for i in 0..processes.len(){
        if processes[i].name.to_lowercase()==pname.to_lowercase(){
            return Process::get_process_info_by_id(processes[i].pid);
        }
    }

    return Err("Something went wrong".to_string());

}



pub fn get_peb_address_from_prochandle(prochandle: *mut c_void) -> Result<usize,String>{


    let mut buffer = vec![0u8;std::mem::size_of::<PROCESS_BASIC_INFORMATION>()];

    let mut reqlength = 0;
    let ntstatus = unsafe{NtQueryInformationProcess(prochandle,0,
                                                    buffer.as_mut_ptr() as *mut c_void,buffer.len() as u32,&mut reqlength)};

    //unsafe{CloseHandle(prochandle)};

    if NT_SUCCESS(ntstatus){
        let pbi = parse_structure_from_memory::<PROCESS_BASIC_INFORMATION>(unsafe{GetCurrentProcess()},buffer.as_ptr() as usize).unwrap();

        Ok(pbi.PebBaseAddress as usize)
    }

    else{
        Err(format!("unable to get peb addresss"))
    }

}

pub fn processchecker(pname:&str,filepath:&str) -> Result<bool,String>{
    // checks if the process with pname exists,
    // if exists then kill it and start a new process of filepath
    // if not exists then start the process of filepath

    let processes = get_processes();
    for i in 0..processes.len(){


        if processes[i].name.to_lowercase()==pname.to_lowercase(){

            let prochandle = unsafe{OpenProcess(PROCESS_ALL_ACCESS,0,processes[i].pid)};
            if prochandle.is_null(){
                return Err(format!("Unable to open handle to the process: {}",unsafe{GetLastError()}));
            }
            else{
                let res = unsafe{TerminateProcess(prochandle,0)};
                unsafe{CloseHandle(prochandle)};
                if res==0{

                    return Err(format!("Unable to terminate process: {}",unsafe{GetLastError()}));

                }

            }

        }
    }


    // creating new instance of the process
    let mut si = unsafe{std::mem::zeroed::<STARTUPINFOA>()};
    si.cb = std::mem::size_of::<STARTUPINFOA>() as u32;

    let mut pi = unsafe{std::mem::zeroed::<PROCESS_INFORMATION>()};

    let mut v = filepath.bytes().collect::<Vec<u8>>();
    v.push(0);
    unsafe{CreateProcessA(v.as_ptr() as *const i8,
                          std::ptr::null_mut(),std::ptr::null_mut(),std::ptr::null_mut(),
                          0,0,std::ptr::null_mut(),std::ptr::null_mut(),
                          &mut si,&mut pi)};

    Ok(false)
}

pub fn processcheckerwithargs(pname:&str, filepath:&str,arguments:&str) -> Result<bool,String>{
    // checks if the process with pname exists,
    // if exists then kill it and start a new process of filepath
    // if not exists then start the process of filepath



    let processes = get_processes();
    for i in 0..processes.len(){


        if processes[i].name.to_lowercase()==pname.to_lowercase(){

            let prochandle = unsafe{OpenProcess(PROCESS_ALL_ACCESS,0,processes[i].pid)};
            if prochandle.is_null(){
                return Err(format!("Unable to open handle to the process: {}",unsafe{GetLastError()}));
            }
            else{
                let res = unsafe{TerminateProcess(prochandle,0)};
                unsafe{CloseHandle(prochandle)};
                if res==0{

                    return Err(format!("Unable to terminate process: {}",unsafe{GetLastError()}));

                }

            }

        }
    }


    // creating new instance of the process
    let mut si = unsafe{std::mem::zeroed::<STARTUPINFOA>()};
    si.cb = std::mem::size_of::<STARTUPINFOA>() as u32;

    let mut pi = unsafe{std::mem::zeroed::<PROCESS_INFORMATION>()};

    let mut v = filepath.bytes().collect::<Vec<u8>>();
    v.push(0);
    let mut arg = arguments.bytes().collect::<Vec<u8>>();
    arg.push(0);

    let res = unsafe{CreateProcessA(v.as_mut_ptr() as *mut i8,
                                    arg.as_mut_ptr() as *mut i8,std::ptr::null_mut(),std::ptr::null_mut(),
                                    0,0,std::ptr::null_mut(),std::ptr::null_mut(),
                                    &mut si,&mut pi)};


    Ok(false)
}




pub fn processkiller(pname:&str){

    let p = get_processes();

    for i in 0..p.len(){
        if p[i].get_process_name().to_lowercase() == pname.to_lowercase(){

            let prochandle = unsafe{OpenProcess(PROCESS_ALL_ACCESS,0,p[i].pid)};
            if prochandle.is_null(){
            }
            else{
                let res = unsafe{TerminateProcess(prochandle,0)};
                unsafe{CloseHandle(prochandle)};
                if res==0{


                }

            }

        }
    }

}



pub fn get_processes_from_createtoolhelp32snapshot() -> Result<Vec<Process>,String>{

    let snaphandle = unsafe{CreateToolhelp32Snapshot(0x2,0)};
    if snaphandle==INVALID_HANDLE_VALUE{
        // return Err(format!("CreateToolhelp32Snapshot failed: {}",unsafe{GetLastError()}));
    }

    let mut pentry = unsafe{std::mem::zeroed::<PROCESSENTRY32W>()};
    pentry.dwSize = unsafe{std::mem::size_of_val(&pentry)} as u32;

    let res = unsafe{Process32FirstW(snaphandle,&mut pentry)} ;


    // 18 for ERROR_NO_MORE_FILES
    if res==0 || res==18{
        return Err(format!("Process32FirstW failed: {}",unsafe{GetLastError()}));
    }

    let mut processes :Vec<Process> = Vec::new();

    let pname = readunicodestringfrommemory(unsafe{GetCurrentProcess()},pentry.szExeFile.as_ptr() as *const c_void);
    processes.push(Process{pid:pentry.th32ProcessID,ppid:pentry.th32ParentProcessID,name:pname,path:"to be found".to_string()});

    loop{
        pentry = unsafe{std::mem::zeroed::<PROCESSENTRY32W>()};
        pentry.dwSize = unsafe{std::mem::size_of_val(&pentry)} as u32;

        let res2 = unsafe{Process32NextW(snaphandle,&mut pentry)};

        if res2==0 || res2== 18{
            break;
        }

        let pname = readunicodestringfrommemory(unsafe{GetCurrentProcess()},pentry.szExeFile.as_ptr() as *const c_void);
        processes.push(Process{pid:pentry.th32ProcessID,ppid:pentry.th32ParentProcessID,name:pname,path:"to be found".to_string()});

    }

    Ok(processes)






}



pub fn readunicodestringfrommemory(prochandle:*mut c_void,base:*const c_void)
                                   -> String{
    unsafe{

        let mut buffer:Vec<u8> = Vec::new();
        let mut i = 0;

        loop{
            let mut bytesread = 0;
            let mut temp:u16= 0;
            ReadProcessMemory(prochandle,
                              (base as usize + (i*2)) as *const c_void,
                              &mut temp as *mut _ as *mut c_void,
                              2, &mut bytesread);

            i+=1;
            if temp==0{
                break;
            }


            buffer.push(temp as u8);


        }

        return  String::from_utf8_lossy(&buffer).to_string();



    }
}