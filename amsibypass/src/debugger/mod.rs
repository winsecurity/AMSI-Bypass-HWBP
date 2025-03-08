mod debug_event_handlers;

use winapi::ctypes::*;
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
use crate::utils::{parse_structure_from_memory, ReadStringFromMemory};
use std::collections::*;
use std::io::Read;
use ntapi::ntrtl::RTL_USER_PROCESS_PARAMETERS;
use winapi::um::winbase::*;
use winapi::um::debugapi::*;
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress, LoadLibraryA};
use winapi::um::minwinbase::{CREATE_PROCESS_DEBUG_INFO, DEBUG_EVENT, EXCEPTION_ACCESS_VIOLATION, EXCEPTION_BREAKPOINT, EXCEPTION_FLT_DIVIDE_BY_ZERO};
use crate::process_manager::enumeration::readunicodestringfrommemory;

pub struct debugger{
    processinformation: PROCESS_INFORMATION,
    debugactive: bool,
    softwarebreakpoints: HashMap<usize,u8>,
    hardwarebreakpoints: HashMap<u8,(usize,u8,u32)>
}


impl debugger{

    pub fn launch_executable(path: &str) -> Result<Self,String>{

        let res = create_debug_process(path);

        if res.is_err(){
            Err(res.err().unwrap())
        }

        else{
            Ok(Self{processinformation: res.unwrap(),debugactive: true,
            softwarebreakpoints: HashMap::new(),hardwarebreakpoints: HashMap::new()})
        }

    }


    pub fn attach_to_process(pid: u32) -> Result<Self,String>{

        let prochandle = unsafe{OpenProcess(PROCESS_ALL_ACCESS,0,pid)};

        if prochandle.is_null(){
            return Err(format!("OpenProcess failed: {}",unsafe{GetLastError()}));
        }

        let res = unsafe{DebugActiveProcess(pid)};
        if res==0{
            unsafe{CloseHandle(prochandle)};
            return Err(format!("Attaching to process with DebugActiveProcess failed: {}",unsafe{GetLastError()}));
        }


        let debugevent = Self::wait_for_debug_event(0xFFFFFFFF).unwrap();

        let mut pi = unsafe{std::mem::zeroed::<PROCESS_INFORMATION>()};
        pi.dwProcessId = debugevent.dwProcessId;
        pi.dwThreadId = debugevent.dwThreadId;
        pi.hProcess = prochandle;
        let threadhandle = unsafe{OpenThread(THREAD_ALL_ACCESS,0,debugevent.dwThreadId)};
        pi.hThread = threadhandle;

        let mut dbg = (Self{processinformation:pi,
            debugactive:true,softwarebreakpoints:HashMap::new(),
        hardwarebreakpoints:HashMap::new(),});


        dbg.handle_debug_event(&debugevent);

        Ok(dbg)


        /*let res =  unsafe{ContinueDebugEvent(debugevent.dwProcessId,debugevent.dwThreadId,DBG_CONTINUE)};
        if res==0{
            unsafe{CloseHandle(prochandle)};
            return Err(format!("ContinueDebugEvent failed: {}",unsafe{GetLastError()}));
        }*/


    }


    pub fn set_software_breakpoint(&mut self, address: usize) -> Result<u8,String>{

        for (baddress,value) in self.softwarebreakpoints.iter(){
            if *baddress == address{
                return Err(format!("Software Breakpoint already exists"));
            }
        }

        let mut oldprotect = 0;
        unsafe{VirtualProtectEx(self.processinformation.hProcess,address as *mut c_void,
        1,PAGE_READWRITE,&mut oldprotect)};


        let mut buffer:Vec<u8> = vec![0u8];
        let mut bytesread = 0;
        let res = unsafe{ReadProcessMemory(self.processinformation.hProcess,address as *const c_void,
        buffer.as_mut_ptr() as *mut c_void,1,&mut bytesread)};

        if res==0 && bytesread == 0{
            // restoring page protection
            unsafe{VirtualProtectEx(self.processinformation.hProcess,address as *mut c_void,
                                    1,oldprotect,&mut oldprotect)};


            return Err(format!("ReadProcessMemory failed: {}",unsafe{GetLastError()}));

        }


        let mut ccbuffer = vec![0xccu8];
        let mut byteswritten = 0;
        let res =unsafe{WriteProcessMemory(self.processinformation.hProcess,address as *mut c_void,
        ccbuffer.as_ptr() as *const c_void,1,&mut byteswritten)};

        if res!=0 && byteswritten==1{
            self.softwarebreakpoints.insert(address,buffer[0]);
        }

        // restoring page protection
        unsafe{VirtualProtectEx(self.processinformation.hProcess,address as *mut c_void,
                                1,oldprotect,&mut oldprotect)};


        Ok(1)
    }


    pub fn restore_software_breakpoint(&mut self, address: usize) -> Result<u8,String> {

        let mut isbreakpointexist = false;
        for (baddress,value) in self.softwarebreakpoints.iter(){
            if *baddress == address{
                isbreakpointexist = true;
                break;
            }
        }

        if !isbreakpointexist {
            return Err(format!("Specified software breakpoint does not exist"));
        }


        let mut oldprotect = 0;
        unsafe{VirtualProtectEx(self.processinformation.hProcess,address as *mut c_void,
                                1,PAGE_READWRITE,&mut oldprotect)};




        let mut ccbuffer =  [self.softwarebreakpoints[&address].clone() ];
        let mut byteswritten = 0;
        let res =unsafe{WriteProcessMemory(self.processinformation.hProcess,address as *mut c_void,
                                           ccbuffer.as_ptr() as *const c_void,1,&mut byteswritten)};

        if res!=0 && byteswritten==1{
            self.softwarebreakpoints.remove(&address);
        }

        // restoring page protection
        unsafe{VirtualProtectEx(self.processinformation.hProcess,address as *mut c_void,
                                1,oldprotect,&mut oldprotect)};


        Ok(1)

    }


    pub fn enter_debugging_loop(&mut self,address:usize){

        let mut t=300;
        self.set_hardware_breakpoint(address,1,0);
        while self.debugactive == true{

            /*let res = self.set_hardware_breakpoint(address as usize, 1,0);
            if res.is_err(){
                println!("[+] Failed to set hardware breakpoint!: {}",res.unwrap_err());
            }*/



            let debugevent = Self::wait_for_debug_event(0xFFFFFFFF).unwrap();

            println!("[+] Debug event has occurred: {}",debugevent.dwDebugEventCode);



            let (dbgstatus,toset) =  self.handle_debug_event(&debugevent);


            let res = unsafe{ContinueDebugEvent(debugevent.dwProcessId,debugevent.dwThreadId,dbgstatus)};





            if toset!=0{
                std::thread::sleep(std::time::Duration::from_secs(1));

                //self.set_hardware_breakpoint(address,1,0);


                self.set_hardware_breakpoint_in_thread(address,1,0,toset);
               // self.set_hardware_breakpoint_in_thread(unsafe{debugevent.u.Exception().ExceptionRecord.ExceptionAddress} as usize,1,0,debugevent.dwThreadId);
            }


            //t = t-1;

        }

    }


    fn handle_debug_event(&mut self,debugevent: &DEBUG_EVENT) -> (u32,u32){

        if debugevent.dwDebugEventCode==3{
            debug_event_handlers::create_process_event_handler(debugevent);
        }

        else if debugevent.dwDebugEventCode==6{
            debug_event_handlers::load_dll_event_handler(debugevent);

        }

        // EXCEPTION_DEBUG_EVENT
        else if debugevent.dwDebugEventCode==1{
            println!("[+] EXCEPTION Debug event {} has occurred inside thread {}",
                     debugevent.dwDebugEventCode,debugevent.dwThreadId);

            let exceptioncode = unsafe{debugevent.u.Exception().ExceptionRecord.ExceptionCode};
            let exceptionaddress = unsafe{debugevent.u.Exception().ExceptionRecord.ExceptionAddress};
            println!("Exception code: {}",unsafe{debugevent.u.Exception().ExceptionRecord.ExceptionCode});

            match exceptioncode{
                EXCEPTION_ACCESS_VIOLATION => {
                    println!("EXCEPTION_ACCESS_VIOLATION");
                    println!("Exception address: {:x?}",exceptionaddress);

                    println!("first chance: {}",unsafe{debugevent.u.Exception().dwFirstChance});
                    if unsafe{debugevent.u.Exception().dwFirstChance}==1{
                        return (DBG_EXCEPTION_NOT_HANDLED,0);
                    }

                    return (DBG_CONTINUE,0);
                },
                EXCEPTION_BREAKPOINT => {

                    println!("EXCEPTION_BREAKPOINT");
                    println!("Exception address: {:x?}",exceptionaddress);

                    let mut torestore = false;
                    for (address,value) in self.softwarebreakpoints.iter(){

                        if *address == exceptionaddress as usize{

                            // we need to restore the breakpoint
                           torestore = true;
                            break;
                        }

                    }


                    if torestore==true{


                        let context = self.get_thread_context(debugevent.dwThreadId).unwrap();
                        println!("RIP before restoring breakpoint: {:x?}",context.Rip);

                        let res = self.restore_software_breakpoint(exceptionaddress as usize).unwrap();
                        let mut context = self.get_thread_context(debugevent.dwThreadId).unwrap();


                        let msg = ReadStringFromMemory(self.processinformation.hProcess,context.Rdx as *const c_void);
                        println!("RDX: {}",msg);

                        //let msg2 = ReadStringFromMemory(self.processinformation.hProcess,context.R8 as *const c_void);
                        //println!("R8: {}",msg2);

                        context.Rip =  context.Rip-1;

                        self.set_thread_context(debugevent.dwThreadId, context);




                    }


                },
                EXCEPTION_FLT_DIVIDE_BY_ZERO => {println!("EXCEPTION_FLT_DIVIDE_BY_ZERO");},
                EXCEPTION_SINGLE_STEP => {
                    println!("EXCEPTION_SINGLE_STEP");

                    println!("Exception address: {:x?}",exceptionaddress);

                    let context = self.get_thread_context(debugevent.dwThreadId).unwrap();

                    println!("DR0: {:x?}",context.Dr0);
                    println!("DR1: {:x?}",context.Dr1);
                    println!("DR2: {:x?}",context.Dr2);
                    println!("DR3: {:x?}",context.Dr3);
                    println!("DR7: {:x?}",context.Dr7);


                    unsafe{LoadLibraryA("amsi.dll\0".as_bytes().as_ptr() as *const i8)};
                    let amsidll = unsafe{GetModuleHandleA("amsi.dll\0".as_bytes().as_ptr() as *const i8)};
                    let messageboxaddress = unsafe{GetProcAddress(amsidll,"AmsiScanBuffer\0".as_bytes().as_ptr() as *const i8)};


                    if messageboxaddress as usize ==exceptionaddress as usize {
                            // in AmsiScanBuffer() RDX holds buffer content
                            // R8 holds length of buffer to examine,
                            // we can change the length to 1
                            //let msg = ReadStringFromMemory(self.processinformation.hProcess,context.Rdx as *const c_void);
                            //let content = readunicodestringfrommemory(self.processinformation.hProcess,context.Rdx as *const c_void);
                            println!("RDX: {:x?}",context.Rdx);
                            //println!("unicode string at rdx: {}",content);
                            //let msg2 = ReadStringFromMemory(self.processinformation.hProcess,context.R8 as *const c_void);
                            println!("R8: {}",context.R8);

                            self.clear_hardware_breakpoint(exceptionaddress as usize,debugevent.dwThreadId,&context);


                            return (DBG_EXCEPTION_HANDLED,debugevent.dwThreadId);

                    }


                    return (DBG_EXCEPTION_NOT_HANDLED,0);
                },
                _ => {}
            }

            //println!("Exception address: {:x?}",unsafe{debugevent.u.Exception().ExceptionRecord.ExceptionAddress});

            return (DBG_EXCEPTION_NOT_HANDLED,0);
        }

        (DBG_CONTINUE,0)
    }


    pub fn continue_debug_event(&self,pid:u32, tid:u32,dbgstatus: u32) -> Result<u8,String>{

        let res = unsafe{ContinueDebugEvent(pid,tid,dbgstatus)};

        if res==0{
            return Err(format!("Continuing debug event failed: {}",unsafe{GetLastError()}));
        }

        Ok(1) // 1 for successfully continued
    }

    pub fn wait_for_debug_event(time:u32) -> Result<DEBUG_EVENT,String>{


            let mut debugevent = unsafe{std::mem::zeroed::<DEBUG_EVENT>()};
            let res = unsafe{WaitForDebugEvent(&mut debugevent,time)};
            if res==0{
                return Err(format!("WaitingforDebugEvent with WaitForDebugEvent failed: {}",unsafe{GetLastError()}));
            }

            Ok(debugevent)



    }


    pub fn set_hardware_breakpoint(&mut self, address: usize, length: u8, condition: u32) -> Result<u8,String>{

        /*for (available,(addr,len1,cond)) in self.hardwarebreakpoints.iter(){

            if *addr==address{
                return Err(format!("Hardware breakpoint at {:x?} already exists",address))
            }

        }*/

        let mut availableregister = 100;
        if length==1 || length==2 || length==4 || length==8{
        }
        else{
            return Err(format!("Can only set hardware breakpoint of lengths 1,2,4 and 8"));

        }

        /*let mut availableregister = 10;
        if !self.hardwarebreakpoints.contains_key(&0){
            availableregister = 0;
        }

        else if !self.hardwarebreakpoints.contains_key(&1){
            availableregister = 1;
        }

        else if !self.hardwarebreakpoints.contains_key(&2){
            availableregister = 2;
        }
        else if !self.hardwarebreakpoints.contains_key(&3){
            availableregister = 3;
        }
        else{
             // return Err(format!("All four hardware breakpoints are already present"));
        }*/


        let threadids = self.get_all_threads(self.processinformation.dwProcessId).unwrap();
        for i in 0..threadids.len(){

           let context =  self.get_thread_context(threadids[i].th32ThreadID);

            if context.is_ok(){

                let mut context = context.unwrap();

                if context.Dr0 ==0 || context.Dr0 == address as u64{
                    context.Dr0 = address as u64;
                    availableregister = 0;
                    // setting last lsb bit to 1 to enable DR0 breakpoint
                    context.Dr7 |= 1 as u64;

                    // 17th, 18th bit defines the condition that
                    // triggers dr0 breakpoint
                    // we need to set those bits to the condition value

                    // clearing off our condition bits with & 11111100 11111111 11111111

                    context.Dr7 &=  0xFF_FF_FF_FF_FF_FC_FF_FF;

                    // now we can OR with our condition bits to set
                    // inside dr7's 17th bit, 18th bit

                    match condition{
                        0 =>{
                            // 0 for execution only
                            // AND with 111111001111111111111111 to set 17th, 18th bit to zeroes
                            context.Dr7 &= 0xFF_FF_FF_FF_FC_FF_FF;
                        },
                        1=>{
                            // 1 for WRITE ONLY

                            context.Dr7 |= 0b010000000000000000;

                        },
                        3=>{
                            // 3 for READ_WRITE ACCESS
                            // OR with 110000000000000000, which sets 17th and 18th bit
                            context.Dr7 |= 0b110000000000000000;
                        },
                        _ => {}
                    }


                    // clearing off the length bits 19th, 20th bit for DR0 register
                    context.Dr7 &= 0xFF_FF_FF_FF_FF_F3_FF_FF;
                    // 00 - 1 byte
                    // 01 - 2 bytes
                    // 10 - 8 bytes
                    // 11 - 4 bytes
                    match length{
                        1=> {
                            context.Dr7 &= 0xFF_FF_FF_FF_FF_F3_FF_FF;
                        },
                        2 => {
                            // 20bits
                            context.Dr7 |= 0b01000000000000000000;

                        },
                        8 => {
                            // 20bits
                            context.Dr7 |= 0b10000000000000000000;

                        },
                        4=>{
                            // 20bits
                            context.Dr7 |= 0b11000000000000000000;

                        }
                        _=> {}
                    }


                }

                else if context.Dr1 ==0 || context.Dr1 == address as u64{
                    context.Dr1 = address as u64;
                    availableregister = 1;
                    // setting 3rd bit to 1 to enable DR1 breakpoint
                    context.Dr7 |= 4 as u64;


                    // clearing off 21,22 bits for dr1 breakpoint
                    context.Dr7 &= 0xFF_FF_FF_FF_FF_CF_FF_FF;


                    match condition{
                        0 =>{
                            // 0 for execution only
                            context.Dr7 &= 0xFF_FF_FF_FF_FF_CF_FF_FF;

                        },
                        1=>{
                            // 1 for WRITE ONLY

                            context.Dr7 |= 0b0100000000000000000000;

                        },
                        3=>{
                            // 3 for READ_WRITE ACCESS
                            // setting 21st 22nd bits
                            context.Dr7 |= 0b1100000000000000000000;
                        },
                        _ => {}
                    }

                    // clearing off the length bits 23th, 24th bit for DR0 register
                    context.Dr7 &= 0xFF_FF_FF_FF_FF_3F_FF_FF;

                    // 00 - 1 byte
                    // 01 - 2 bytes
                    // 10 - 8 bytes
                    // 11 - 4 bytes
                    match length{
                        1=> {
                            context.Dr7 &= 0xFF_FF_FF_FF_FF_3F_FF_FF;
                        },
                        2 => {
                            // 20bits
                            context.Dr7 |= 0b01000000000000000000_0000;

                        },
                        8 => {
                            // 20bits
                            context.Dr7 |= 0b10000000000000000000_0000;

                        },
                        4=>{
                            // 20bits
                            context.Dr7 |= 0b11000000000000000000_0000;

                        }
                        _=> {}
                    }



                }
                else if context.Dr2 ==0 || context.Dr2 == address as u64{
                    context.Dr2 = address as u64;
                    availableregister = 2;
                    // setting 5th bit to 1 to enable DR2 breakpoint

                    context.Dr7 |= 16 as u64;



                    // clearing off 25, 26 bits for dr2 breakpoint
                    context.Dr7 &= 0xFF_FF_FF_FF_FC_FF_FF_FF;


                    match condition{
                        0 =>{
                            // 0 for execution only
                            context.Dr7 &= 0xFF_FF_FF_FF_FC_FF_FF_FF;

                        },
                        1=>{
                            // 1 for WRITE ONLY

                            context.Dr7 |= 0b0100000000000000000000_0000;

                        },
                        3=>{
                            // 3 for READ_WRITE ACCESS

                            context.Dr7 |= 0b1100000000000000000000_0000;
                        },
                        _ => {}
                    }

                    // clearing off the length bits 27, 28 bit for DR2 register
                    context.Dr7 &= 0xFF_FF_FF_FF_F3_FF_FF_FF;



                    // 00 - 1 byte
                    // 01 - 2 bytes
                    // 10 - 8 bytes
                    // 11 - 4 bytes
                    match length{
                        1=> {
                            context.Dr7 &= 0xFF_FF_FF_FF_F3_FF_FF_FF;
                        },
                        2 => {

                            context.Dr7 |= 0b01000000000000000000_0000_0000;

                        },
                        8 => {

                            context.Dr7 |= 0b10000000000000000000_0000_0000;

                        },
                        4=>{

                            context.Dr7 |= 0b11000000000000000000_0000_0000;

                        }
                        _=> {}
                    }


                }
                else if context.Dr3 ==0 || context.Dr3 == address as u64{
                    context.Dr3 = address as u64;
                    availableregister = 3;
                    // setting 7th bit to 1 to enable DR3 breakpoint

                    context.Dr7 |= 64 as u64;



                    // clearing off 29, 30 bits for dr3 breakpoint
                    context.Dr7 &= 0xFF_FF_FF_FF_CF_FF_FF_FF;


                    match condition{
                        0 =>{
                            // 0 for execution only
                            context.Dr7 &= 0xFF_FF_FF_FF_CF_FF_FF_FF;

                        },
                        1=>{
                            // 1 for WRITE ONLY

                            context.Dr7 |= 0b0100000000000000000000_0000_0000;

                        },
                        3=>{
                            // 3 for READ_WRITE ACCESS

                            context.Dr7 |= 0b1100000000000000000000_0000_0000;
                        },
                        _ => {}
                    }


                    // clearing off the length bits 31,32 bit for DR2 register
                    context.Dr7 &= 0xFF_FF_FF_FF_3F_FF_FF_FF;

                    // 00 - 1 byte
                    // 01 - 2 bytes
                    // 10 - 8 bytes
                    // 11 - 4 bytes
                    match length{
                        1=> {
                            context.Dr7 &= 0xFF_FF_FF_FF_3F_FF_FF_FF;
                        },
                        2 => {

                            context.Dr7 |= 0b01000000000000000000_0000_0000_0000;

                        },
                        8 => {

                            context.Dr7 |= 0b10000000000000000000_0000_0000_0000;

                        },
                        4=>{

                            context.Dr7 |= 0b11000000000000000000_0000_0000_0000;

                        }
                        _=> {}
                    }

                }
                else{
                    return Err(format!("all dr0-3 registers are occupied"));
                }

                //context.Dr7 |= (condition << ((availableregister * 4) + 16) )  as u64;

               // context.Dr7 |= (length << ((availableregister * 4) + 18)) as u64;

                let res = self.set_thread_context(threadids[i].th32ThreadID,context);
                if res.is_err(){
                    println!("setting thread context failed: {}",res.err().unwrap());
                }

                /*if res.is_ok(){
                    self.hardwarebreakpoints.insert(availableregister,(address,length,condition));
                }*/



            }


        }

        Ok(1)

    }

    pub fn set_hardware_breakpoint_in_thread(&mut self,address: usize, length: u8, condition: u32,tid:u32){


        let context =  self.get_thread_context(tid);

        if context.is_ok(){

            let mut context = context.unwrap();

            if context.Dr0 ==0{
                context.Dr0 = address as u64;

                // setting last lsb bit to 1 to enable DR0 breakpoint
                context.Dr7 |= 1 as u64;

                // 17th, 18th bit defines the condition that
                // triggers dr0 breakpoint
                // we need to set those bits to the condition value

                // clearing off our condition bits with & 11111100 11111111 11111111

                context.Dr7 &=  0xFF_FF_FF_FF_FF_FC_FF_FF;

                // now we can OR with our condition bits to set
                // inside dr7's 17th bit, 18th bit

                match condition{
                    0 =>{
                        // 0 for execution only
                        // AND with 111111001111111111111111 to set 17th, 18th bit to zeroes
                        context.Dr7 &= 0xFF_FF_FF_FF_FC_FF_FF;
                    },
                    1=>{
                        // 1 for WRITE ONLY

                        context.Dr7 |= 0b010000000000000000;

                    },
                    3=>{
                        // 3 for READ_WRITE ACCESS
                        // OR with 110000000000000000, which sets 17th and 18th bit
                        context.Dr7 |= 0b110000000000000000;
                    },
                    _ => {}
                }


                // clearing off the length bits 19th, 20th bit for DR0 register
                context.Dr7 &= 0xFF_FF_FF_FF_FF_F3_FF_FF;
                // 00 - 1 byte
                // 01 - 2 bytes
                // 10 - 8 bytes
                // 11 - 4 bytes
                match length{
                    1=> {
                        context.Dr7 &= 0xFF_FF_FF_FF_FF_F3_FF_FF;
                    },
                    2 => {
                        // 20bits
                        context.Dr7 |= 0b01000000000000000000;

                    },
                    8 => {
                        // 20bits
                        context.Dr7 |= 0b10000000000000000000;

                    },
                    4=>{
                        // 20bits
                        context.Dr7 |= 0b11000000000000000000;

                    }
                    _=> {}
                }


            }

            else if context.Dr1 ==0{
                context.Dr1 = address as u64;

                // setting 3rd bit to 1 to enable DR1 breakpoint
                context.Dr7 |= 4 as u64;


                // clearing off 21,22 bits for dr1 breakpoint
                context.Dr7 &= 0xFF_FF_FF_FF_FF_CF_FF_FF;


                match condition{
                    0 =>{
                        // 0 for execution only
                        context.Dr7 &= 0xFF_FF_FF_FF_FF_CF_FF_FF;

                    },
                    1=>{
                        // 1 for WRITE ONLY

                        context.Dr7 |= 0b0100000000000000000000;

                    },
                    3=>{
                        // 3 for READ_WRITE ACCESS
                        // setting 21st 22nd bits
                        context.Dr7 |= 0b1100000000000000000000;
                    },
                    _ => {}
                }

                // clearing off the length bits 23th, 24th bit for DR0 register
                context.Dr7 &= 0xFF_FF_FF_FF_FF_3F_FF_FF;

                // 00 - 1 byte
                // 01 - 2 bytes
                // 10 - 8 bytes
                // 11 - 4 bytes
                match length{
                    1=> {
                        context.Dr7 &= 0xFF_FF_FF_FF_FF_3F_FF_FF;
                    },
                    2 => {
                        // 20bits
                        context.Dr7 |= 0b01000000000000000000_0000;

                    },
                    8 => {
                        // 20bits
                        context.Dr7 |= 0b10000000000000000000_0000;

                    },
                    4=>{
                        // 20bits
                        context.Dr7 |= 0b11000000000000000000_0000;

                    }
                    _=> {}
                }



            }
            else if context.Dr2 ==0{
                context.Dr2 = address as u64;

                // setting 5th bit to 1 to enable DR2 breakpoint

                context.Dr7 |= 16 as u64;



                // clearing off 25, 26 bits for dr2 breakpoint
                context.Dr7 &= 0xFF_FF_FF_FF_FC_FF_FF_FF;


                match condition{
                    0 =>{
                        // 0 for execution only
                        context.Dr7 &= 0xFF_FF_FF_FF_FC_FF_FF_FF;

                    },
                    1=>{
                        // 1 for WRITE ONLY

                        context.Dr7 |= 0b0100000000000000000000_0000;

                    },
                    3=>{
                        // 3 for READ_WRITE ACCESS

                        context.Dr7 |= 0b1100000000000000000000_0000;
                    },
                    _ => {}
                }

                // clearing off the length bits 27, 28 bit for DR2 register
                context.Dr7 &= 0xFF_FF_FF_FF_F3_FF_FF_FF;



                // 00 - 1 byte
                // 01 - 2 bytes
                // 10 - 8 bytes
                // 11 - 4 bytes
                match length{
                    1=> {
                        context.Dr7 &= 0xFF_FF_FF_FF_F3_FF_FF_FF;
                    },
                    2 => {

                        context.Dr7 |= 0b01000000000000000000_0000_0000;

                    },
                    8 => {

                        context.Dr7 |= 0b10000000000000000000_0000_0000;

                    },
                    4=>{

                        context.Dr7 |= 0b11000000000000000000_0000_0000;

                    }
                    _=> {}
                }


            }
            else if context.Dr3 ==3{
                context.Dr3 = address as u64;

                // setting 7th bit to 1 to enable DR3 breakpoint

                context.Dr7 |= 64 as u64;



                // clearing off 29, 30 bits for dr3 breakpoint
                context.Dr7 &= 0xFF_FF_FF_FF_CF_FF_FF_FF;


                match condition{
                    0 =>{
                        // 0 for execution only
                        context.Dr7 &= 0xFF_FF_FF_FF_CF_FF_FF_FF;

                    },
                    1=>{
                        // 1 for WRITE ONLY

                        context.Dr7 |= 0b0100000000000000000000_0000_0000;

                    },
                    3=>{
                        // 3 for READ_WRITE ACCESS

                        context.Dr7 |= 0b1100000000000000000000_0000_0000;
                    },
                    _ => {}
                }


                // clearing off the length bits 31,32 bit for DR2 register
                context.Dr7 &= 0xFF_FF_FF_FF_3F_FF_FF_FF;

                // 00 - 1 byte
                // 01 - 2 bytes
                // 10 - 8 bytes
                // 11 - 4 bytes
                match length{
                    1=> {
                        context.Dr7 &= 0xFF_FF_FF_FF_3F_FF_FF_FF;
                    },
                    2 => {

                        context.Dr7 |= 0b01000000000000000000_0000_0000_0000;

                    },
                    8 => {

                        context.Dr7 |= 0b10000000000000000000_0000_0000_0000;

                    },
                    4=>{

                        context.Dr7 |= 0b11000000000000000000_0000_0000_0000;

                    }
                    _=> {}
                }

            }


            //context.Dr7 |= (condition << ((availableregister * 4) + 16) )  as u64;

            // context.Dr7 |= (length << ((availableregister * 4) + 18)) as u64;

            let res = self.set_thread_context(tid,context);



        }

    }

    pub fn clear_hardware_breakpoint(&mut self,address: usize,tid: u32,context1: &CONTEXT) -> Result<u8,String>{

        // we need to clear off the bit in DR7 register

        let mut context = (*context1).clone();

        let mut availabletoremove =99;
        let mut available = 100;
        let mut ispresent = false;





                //let mut context =  self.get_thread_context(debugevent.dwThreadId).unwrap();

                if context.Dr0 as usize==address {

                    // clearing off first LSB bit for local breakpoint in DR7


                    context.Dr7 &= 0xFF_FF_FF_FF_FF_FF_FF_FE;

                    // clearing off second LSB bit for global breakpoint in DR7
                    //context.Dr7 &= 0xFF_FF_FF_FF_FF_FF_FF_FD;


                    context.Dr0 = 0;
                    available = 0;

                }
                else if context.Dr1 as usize == address{

                    context.Dr7 &= 0xFF_FF_FF_FF_FF_FF_FF_FB;


                    context.Dr7 &= 0xFF_FF_FF_FF_FF_FF_FF_F7;

                    context.Dr1 = 0;

                    available = 1;
                }
            else if context.Dr2 == address as u64{


                // disabling local bp for dr2 register, 5th bit
                context.Dr7 &= 0xFF_FF_FF_FF_FF_FF_FF_EF;

                // disabling 6th bit for global bp for dr2 register
                context.Dr7 &= 0xFF_FF_FF_FF_FF_FF_FF_DF;




                context.Dr2 = 0;
                available = 2;

            }

            else if context.Dr3 == address as u64{

                // disabling local bp for dr3 register, 7th bit
                context.Dr7 &= 0xFF_FF_FF_FF_FF_FF_FF_BF;

                // disabling 8th bit for global bp for dr2 register
                context.Dr7 &= 0xFF_FF_FF_FF_FF_FF_FF_7F;



                context.Dr3 = 0;
                available = 3;

            }
        else{
            return Err(format!("No hardware breakpoint was found in that thread"));
        }

        context.Dr6 = 0;
        context.EFlags = 0;

        //context.Dr7 &= !(3 << ((available * 4) + 16));
        //context.Dr7 &= !(3 << ((available * 4) + 18));

        context.R8 = 1;

        let res = self.set_thread_context(tid,context);

        if res.is_err(){
            println!("setting thread context failed: {}",res.err().unwrap());
        }


        let latestcontext = self.get_thread_context(tid).unwrap();

        println!("After clearing hwbp");

        println!("DR0: {:x?}",latestcontext.Dr0);
        println!("DR1: {:x?}",latestcontext.Dr1);
        println!("DR2: {:x?}",latestcontext.Dr2);
        println!("DR3: {:x?}",latestcontext.Dr3);
        println!("DR6: {:x?}",latestcontext.Dr6);
        println!("DR7: {:x?}",latestcontext.Dr7);
        println!("R8: {}", latestcontext.R8);

        //availabletoremove = *available;







        //self.hardwarebreakpoints.remove(&availabletoremove);

        /*if ispresent == true{
            println!("before removing hwbps: {:x?}",self.hardwarebreakpoints);
            //self.hardwarebreakpoints.remove(&availabletoremove);
            println!("current hwbps: {:x?}",self.hardwarebreakpoints);
        }*/
        //self.set_hardware_breakpoint(address,1,0);

        Ok(1)
    }


    pub fn clear_hardware_breakpoint_in_all_threads(&mut self, address: usize,context1: &CONTEXT){

        let threadids = self.get_all_threads(self.processinformation.dwProcessId).unwrap();

        for i in 0..threadids.len(){

            self.clear_hardware_breakpoint(address,threadids[i].th32ThreadID,context1);

        }

    }


    pub fn detach(&self) -> Result<(),String>{
        let res = unsafe{DebugActiveProcessStop(self.processinformation.dwProcessId)};
        if res==0{

            return Err(format!(" DebugActiveProcessStopfailed: {}",unsafe{GetLastError()}));
        }
        Ok(())
    }


    pub fn get_thread_context(&self,tid:u32) -> Result<CONTEXT,String>{
        let threadhandle =   unsafe{OpenThread(THREAD_ALL_ACCESS,0,tid)};

        if threadhandle.is_null(){
            return Err(format!("[+] OpenThread failed: {}",unsafe{GetLastError()}));
        }


        let mut context = unsafe{std::mem::zeroed::<CONTEXT>()};
        context.ContextFlags = CONTEXT_ALL;
        let res = unsafe{GetThreadContext(threadhandle,&mut context)};

        if res==0{
            unsafe{CloseHandle(threadhandle)};
            return Err(format!("[+] GetThreadContext failed: {}",unsafe{GetLastError()}));
        }
        unsafe{CloseHandle(threadhandle)};
        Ok(context)


    }


    pub fn set_thread_context(&self,tid:u32,mut context: CONTEXT) -> Result<u8,String>{
        let threadhandle =   unsafe{OpenThread(THREAD_ALL_ACCESS,0,tid)};

        if threadhandle.is_null(){
            return Err(format!("[+] OpenThread failed: {}",unsafe{GetLastError()}));
        }



        let res = unsafe{SetThreadContext(threadhandle,&mut context)};

        if res==0{
            unsafe{CloseHandle(threadhandle)};
            return Err(format!("[+] SetThreadContext failed: {}",unsafe{GetLastError()}));
        }
        unsafe{CloseHandle(threadhandle)};
        Ok(1)


    }

    pub fn get_all_threads(&self,pid: u32) -> Result<Vec<THREADENTRY32>,String>{
        let p = crate::process_manager::enumeration::get_processes();
        for i in 0..p.len(){
            if p[i].get_process_id()==pid{
               return p[i].get_threadids();
            }
        }

        Err(format!("Cannot find process id"))

    }

    pub fn get_debuggee_process_id(&self) -> u32 {
        self.processinformation.dwProcessId
    }

    pub fn get_debuggee_thread_id(&self) -> u32 {
        self.processinformation.dwThreadId
    }



}


impl Drop for debugger{

    fn drop(&mut self){

        if !self.processinformation.hProcess.is_null(){
            unsafe{CloseHandle(self.processinformation.hProcess)};
        }
        if !self.processinformation.hThread.is_null(){
            unsafe{CloseHandle(self.processinformation.hThread)};
        }
    }

}


fn create_debug_process(path:&str) ->Result<PROCESS_INFORMATION, String>{
    let mut buffer = path.bytes().collect::<Vec<u8>>();
    buffer.push(b'\0');


    let mut pi = unsafe{std::mem::zeroed::<PROCESS_INFORMATION>()};

    let mut si = unsafe{std::mem::zeroed::<STARTUPINFOA>()};
    si.cb = unsafe{std::mem::size_of::<STARTUPINFOA>()} as u32 ;

    si.dwFlags = 1 ;
    si.wShowWindow = 0;

    let res = unsafe{CreateProcessA(buffer.as_ptr() as *const i8
                                    ,std::ptr::null_mut(),std::ptr::null_mut(),
                                    std::ptr::null_mut(),0,
                                    DEBUG_PROCESS,std::ptr::null_mut(),std::ptr::null_mut(),
                                    &mut si, &mut pi)};

    if res==0{
        return Err(format!("CreateProcessA failed: {}",unsafe{GetLastError()}));
    }


    Ok(pi)
}


