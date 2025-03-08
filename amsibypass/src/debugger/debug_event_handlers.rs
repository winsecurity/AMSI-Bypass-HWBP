use std::collections::HashMap;
use winapi::um::minwinbase::*;
use winapi::um::processthreadsapi::*;
use crate::utils::ReadStringFromMemory;

pub fn create_process_event_handler(debugevent: &DEBUG_EVENT){
    //println!("[+] Debug event {} has occurred inside process {}",
    //         debugevent.dwDebugEventCode,debugevent.dwProcessId);


    if debugevent.dwDebugEventCode == 3{
        println!("CREATE_PROCESS_EVENT has occurred");


        //let createprocessdebuginfo = parse_structure_from_memory::<CREATE_PROCESS_DEBUG_INFO>(unsafe{GetCurrentProcess()},
        //                           (debugevent  as *const _ as usize +12) as usize).unwrap();


        let imagename = crate::utils::ReadStringFromMemory(unsafe{GetCurrentProcess()},
                                                           unsafe{debugevent.u.CreateProcessInfo().lpImageName});

        println!("Image name: {}",imagename);
        println!("process base: {:x?}",unsafe{debugevent.u.CreateProcessInfo().lpBaseOfImage});



    }


}

pub fn exception_event_handler(debugevent: &DEBUG_EVENT,softwarebreakpoints: HashMap<usize,u8> ){


    if debugevent.dwDebugEventCode == 1{
        println!("[+] EXCEPTION Debug event {} has occurred inside thread {}",
                 debugevent.dwDebugEventCode,debugevent.dwThreadId);

        let exceptioncode = unsafe{debugevent.u.Exception().ExceptionRecord.ExceptionCode};
        let exceptionaddress = unsafe{debugevent.u.Exception().ExceptionRecord.ExceptionAddress};
        println!("Exception code: {}",unsafe{debugevent.u.Exception().ExceptionRecord.ExceptionCode});

        match exceptioncode{
            EXCEPTION_ACCESS_VIOLATION => {println!("EXCEPTION_ACCESS_VIOLATION");},
            EXCEPTION_BREAKPOINT => {

                println!("EXCEPTION_BREAKPOINT");

                for (address,value) in softwarebreakpoints.iter(){

                    if *address == exceptionaddress as usize{

                        // we need to restore the breakpoint



                    }

                }



            },
            EXCEPTION_FLT_DIVIDE_BY_ZERO => {println!("EXCEPTION_FLT_DIVIDE_BY_ZERO");},
            _ => {}
        }

        println!("Exception address: {:x?}",unsafe{debugevent.u.Exception().ExceptionRecord.ExceptionAddress});




    }


}

pub fn load_dll_event_handler(debugevent: &DEBUG_EVENT){

    if debugevent.dwDebugEventCode == 6{
        println!("LOAD_DLL_DEBUG_EVENT has occurred inside thread: {}",debugevent.dwThreadId);


        let dllname = ReadStringFromMemory( unsafe{GetCurrentProcess()},unsafe{debugevent.u.LoadDll().lpImageName});
        println!("DLL Base: {:x?}",unsafe{debugevent.u.LoadDll().lpBaseOfDll});
        //println!("DLL name: {}",dllname);
        //println!("DLL Image name pointer: {:x?}",unsafe{debugevent.u.LoadDll().lpImageName});

        println!();
    }

}

