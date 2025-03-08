use std::collections::*;
use std::io::Read;
use winapi::um::winnt::*;
use winapi::ctypes::*;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::CloseHandle;
use winapi::um::memoryapi::ReadProcessMemory;
use winapi::um::processthreadsapi::*;
use super::utils::*;

pub struct Peparser64{
    buffer: Vec<u8>,
    parsedfromfile: bool
}


#[derive(Debug)]
pub struct importfunctions{
    pub dllname: String,
    pub originalfirstthunk: usize,
    pub functions: HashMap<String,usize>
}


impl importfunctions{
    fn new()->Self{
        importfunctions{dllname:String::new(),originalfirstthunk:0,functions:HashMap::new()}
    }
}


impl Peparser64{

    pub fn parse_from_file(filename:&str) -> Result<Self,String>{
        let res = std::fs::read(filename);

        if res.is_err(){
            Err(format!("{}",res.err().unwrap()))
        }
        else{
            let contents = res.unwrap();

            let parser = Self{buffer:contents,parsedfromfile:true};
            let res = parser.get_ntheader();
            if res.is_err(){
                Err(res.err().unwrap())
            }
            else{
                Ok(parser)
            }


        }

    }


    pub fn parse_from_memory(pid:u32,baseaddress: usize) -> Result<Self,String>{

        let prochandle = unsafe{OpenProcess(PROCESS_VM_READ|PROCESS_QUERY_INFORMATION,0,pid)};

        if !prochandle.is_null(){

            let dosheader = parse_structure_from_memory::<IMAGE_DOS_HEADER>(prochandle,baseaddress).unwrap();
            if dosheader.e_magic!=0x5a4d{
                unsafe{CloseHandle(prochandle)};
                return Err(format!("It's not PE file"));
            }

            let ntheader = parse_structure_from_memory::<IMAGE_NT_HEADERS64>(prochandle,(baseaddress+dosheader.e_lfanew as usize)).unwrap();
            if ntheader.Signature!=0x4550{
                return Err(format!("File is not PE format"));
            }
            if ntheader.FileHeader.Machine!=0x8664 && ntheader.OptionalHeader.Magic!=0x20b{
                return Err(format!("File is not 64 bit PE"));
            }

            let mut contents:Vec<u8> = vec![0;ntheader.OptionalHeader.SizeOfImage as usize] ;
            let mut bytesread = 0;
            let res = unsafe{ReadProcessMemory(prochandle,baseaddress as *const  c_void,
            contents.as_mut_ptr() as *mut c_void,
            contents.len(),&mut bytesread)};

            if res==0{
                unsafe{CloseHandle(prochandle)};
                return Err(format!("reading process memory failed: {}",unsafe{GetLastError()}));

            }




            unsafe{CloseHandle(prochandle)};

            return Ok(Self{buffer:contents,parsedfromfile:false});

        }



        Err(format!("unable to get process handle: {}",unsafe{GetLastError()}))
    }


    pub fn parse_from_memory_handle(prochandle:*mut c_void,baseaddress:usize)-> Result<Self,String>{
        if !prochandle.is_null(){

            let dosheader = parse_structure_from_memory::<IMAGE_DOS_HEADER>(prochandle,baseaddress).unwrap();
            if dosheader.e_magic!=0x5a4d{
                unsafe{CloseHandle(prochandle)};
                return Err(format!("It's not PE file"));
            }

            let ntheader = parse_structure_from_memory::<IMAGE_NT_HEADERS64>(prochandle,(baseaddress+dosheader.e_lfanew as usize)).unwrap();
            if ntheader.Signature!=0x4550{
                return Err(format!("File is not PE format"));
            }
            if ntheader.FileHeader.Machine!=0x8664 && ntheader.OptionalHeader.Magic!=0x20b{
                return Err(format!("File is not 64 bit PE"));
            }

            let mut contents:Vec<u8> = vec![0;ntheader.OptionalHeader.SizeOfImage as usize] ;
            let mut bytesread = 0;
            let res = unsafe{ReadProcessMemory(prochandle,baseaddress as *const  c_void,
                                               contents.as_mut_ptr() as *mut c_void,
                                               contents.len(),&mut bytesread)};

            if res==0{
                unsafe{CloseHandle(prochandle)};
                return Err(format!("reading process memory failed: {}",unsafe{GetLastError()}));

            }




            //unsafe{CloseHandle(prochandle)};

            return Ok(Self{buffer:contents,parsedfromfile:false});

        }
        Err("something went wrong".to_string())
    }


    pub fn get_dosheader(&self) -> Result<IMAGE_DOS_HEADER,String>{

        if self.buffer.len()>64{
            // Checking first 2 magic bytes 4D 5A or not
            if self.buffer[0]!=0x4d && self.buffer[1]!=0x5a{
                return Err(format!("Provided file is not PE format"));
            }

            let dosbytes = &self.buffer[0..63];
            let res = super::utils::parse_structure_from_memory::<IMAGE_DOS_HEADER>(unsafe{GetCurrentProcess()},dosbytes as *const _ as *const c_void as usize);
            match res{
                Ok(dosheader) => {Ok(dosheader)},
                Err(e) => {Err(e.to_owned())}
            }

        }
        else{
            Err(format!("File is not even 64 bytes in length"))
        }

    }

    pub fn get_ntheader(&self) -> Result<IMAGE_NT_HEADERS64,String>{
        let res = self.get_dosheader();
        if res.is_ok(){
            let dosheader = res.unwrap();
            let res = parse_structure_from_memory::<IMAGE_NT_HEADERS64>(unsafe{GetCurrentProcess()},
                                                                        (&self.buffer[dosheader.e_lfanew as usize..]) as *const _ as *const c_void as usize);

            if res.is_ok(){

                let ntheader = res.unwrap();
                if ntheader.Signature!=0x4550{
                    return Err(format!("File is not PE format"));
                }
                if ntheader.FileHeader.Machine!=0x8664 && ntheader.OptionalHeader.Magic!=0x20b{
                    return Err(format!("File is not 64 bit PE"));
                }


                return Ok(ntheader);
            }
            else{
                Err(res.err().unwrap())
            }

        }

        else{
            Err(res.err().unwrap())
        }
    }


    pub fn get_sections(&self) -> Vec<IMAGE_SECTION_HEADER>{
        let dosheader = self.get_dosheader().unwrap();
        let ntheader = self.get_ntheader().unwrap();

        let mut firstsectoffset = dosheader.e_lfanew as usize+std::mem::size_of::<IMAGE_NT_HEADERS64>();
        let mut sections:Vec<IMAGE_SECTION_HEADER> = Vec::new();

        for i in 0..ntheader.FileHeader.NumberOfSections{

           let section = parse_structure_from_memory::<IMAGE_SECTION_HEADER>(unsafe{GetCurrentProcess()}, &self.buffer[firstsectoffset as usize+(i as usize*std::mem::size_of::<IMAGE_SECTION_HEADER>())..]  as *const _ as *const c_void as usize).unwrap();
            sections.push(section);
        }

        sections

    }


    pub fn get_imports(&self) -> Vec<importfunctions>{

        let ntheader = self.get_ntheader().unwrap();
        if ntheader.OptionalHeader.DataDirectory[1].Size==0{
            // return Err(format!("No imports found"));
        }

        if self.parsedfromfile==true{


            let mut firstimportaddr = self.rvatofileoffset(ntheader.OptionalHeader.DataDirectory[1].VirtualAddress as usize).unwrap();

            // looping each import dll

            let mut imports:Vec<importfunctions> =Vec::new();

            'outerloop: loop{

                let mut currentimport = importfunctions::new();

                let imp1 = parse_structure_from_memory::<IMAGE_IMPORT_DESCRIPTOR>(unsafe{GetCurrentProcess()},(self.buffer.as_ptr() as usize+firstimportaddr)).unwrap();

                if imp1.Name==0 && imp1.FirstThunk==0{
                    break 'outerloop;
                }

                let dllname = ReadStringFromMemory(unsafe{GetCurrentProcess()},(self.buffer.as_ptr() as usize + self.rvatofileoffset(imp1.Name as usize).unwrap() ) as *const c_void);

                currentimport.dllname = dllname.trim().to_string();
                currentimport.originalfirstthunk = unsafe{*imp1.u.OriginalFirstThunk()} as usize;

                let mut ogfirstthunk = unsafe{self.buffer.as_ptr() as usize + self.rvatofileoffset(*imp1.u.OriginalFirstThunk() as usize).unwrap()} ;
                let mut firstthunkdata = unsafe{std::ptr::read(ogfirstthunk as *const usize)};

                let mut firstthunkvalue = imp1.FirstThunk as usize;

                // looping each dll's function names
                'innerloop: loop{
                        if firstthunkdata==0{
                            break 'innerloop;
                        }

                    let funcnameptr = unsafe{self.buffer.as_ptr() as usize + self.rvatofileoffset(firstthunkdata).unwrap()} ;
                    let funcname = ReadStringFromMemory(unsafe{GetCurrentProcess()},(funcnameptr+2) as *const c_void );
                    //println!("{}",funcname);

                    currentimport.functions.insert(funcname.trim().to_string(),firstthunkvalue);

                    firstthunkvalue += std::mem::size_of::<usize>();
                    ogfirstthunk += std::mem::size_of::<usize>();
                    firstthunkdata = unsafe{std::ptr::read(ogfirstthunk as *const usize)};

                }

                firstimportaddr += std::mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>();
                //println!();

                imports.push(currentimport);


            }

            imports
        }
        else{

            let mut firstimportaddr = ntheader.OptionalHeader.DataDirectory[1].VirtualAddress as usize;

            // looping each import dll

            let mut imports:Vec<importfunctions> =Vec::new();

            'outerloop: loop{

                let mut currentimport = importfunctions::new();

                let imp1 = parse_structure_from_memory::<IMAGE_IMPORT_DESCRIPTOR>(unsafe{GetCurrentProcess()},(self.buffer.as_ptr() as usize+firstimportaddr)).unwrap();

                if imp1.Name==0 && imp1.FirstThunk==0{
                    break 'outerloop;
                }

                let dllname = ReadStringFromMemory(unsafe{GetCurrentProcess()},(self.buffer.as_ptr() as usize + imp1.Name as usize ) as *const c_void);

                currentimport.dllname = dllname.trim().to_string();
                currentimport.originalfirstthunk = unsafe{*imp1.u.OriginalFirstThunk()} as usize;

                let mut ogfirstthunk = unsafe{self.buffer.as_ptr() as usize + (*imp1.u.OriginalFirstThunk() as usize)} ;
                let mut firstthunkdata = unsafe{std::ptr::read(ogfirstthunk as *const usize)};

                let mut firstthunkvalue = imp1.FirstThunk as usize;

                // looping each dll's function names
                'innerloop: loop{
                    if firstthunkdata==0{
                        break 'innerloop;
                    }

                    let funcnameptr = unsafe{self.buffer.as_ptr() as usize + (firstthunkdata)} ;
                    let funcname = ReadStringFromMemory(unsafe{GetCurrentProcess()},(funcnameptr+2) as *const c_void );
                    //println!("{}",funcname);

                    currentimport.functions.insert(funcname.trim().to_string(),firstthunkvalue);

                    firstthunkvalue += std::mem::size_of::<usize>();
                    ogfirstthunk += std::mem::size_of::<usize>();
                    firstthunkdata = unsafe{std::ptr::read(ogfirstthunk as *const usize)};

                }

                firstimportaddr += std::mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>();
                //println!();

                imports.push(currentimport);


            }

            imports
        }


    }



    pub fn get_exports(&self) -> Result<HashMap<String,usize>,String>{
        let ntheader = self.get_ntheader().unwrap();

        if ntheader.OptionalHeader.DataDirectory[0].Size==0{
             return Err(format!("No exports found"));
        }

        if self.parsedfromfile==true{
            let exportaddr = self.rvatofileoffset(ntheader.OptionalHeader.DataDirectory[0].VirtualAddress as usize).unwrap();
            let export = parse_structure_from_memory::<IMAGE_EXPORT_DIRECTORY>(unsafe{GetCurrentProcess()},self.buffer.as_ptr() as usize + exportaddr).unwrap();

            let dllname = ReadStringFromMemory(unsafe{GetCurrentProcess()},(self.buffer.as_ptr() as usize+(self.rvatofileoffset(export.Name as usize).unwrap() as usize) )as *const c_void);


            let ent = self.buffer.as_ptr() as usize + self.rvatofileoffset(export.AddressOfNames as usize).unwrap();
            let eot = self.buffer.as_ptr() as usize + self.rvatofileoffset(export.AddressOfNameOrdinals as usize).unwrap();
            let eat = self.buffer.as_ptr() as usize + self.rvatofileoffset(export.AddressOfFunctions as usize).unwrap();

            let mut allexports:HashMap<String,usize> = HashMap::new();

            for i in 0..export.NumberOfNames{

                let funcnameoffset = unsafe{std::ptr::read((ent+(i*4) as usize) as *const u32)};
                let funcname = ReadStringFromMemory(unsafe{GetCurrentProcess()},(self.buffer.as_ptr() as usize+(self.rvatofileoffset(funcnameoffset as usize).unwrap()))as *const c_void);


                let ordinaloffset = unsafe{std::ptr::read((eot+(i*2) as usize) as *const u16)};

                let addressoffset = unsafe{std::ptr::read((eat+(ordinaloffset*4) as usize) as *const u32)};

                allexports.insert(funcname,addressoffset as usize);

            }

            Ok(allexports)

        }
        else{
            let exportaddr = ntheader.OptionalHeader.DataDirectory[0].VirtualAddress as usize;
            let export = parse_structure_from_memory::<IMAGE_EXPORT_DIRECTORY>(unsafe{GetCurrentProcess()},self.buffer.as_ptr() as usize + exportaddr).unwrap();

            let dllname = ReadStringFromMemory(unsafe{GetCurrentProcess()},(self.buffer.as_ptr() as usize+(export.Name as usize as usize) )as *const c_void);


            let ent = self.buffer.as_ptr() as usize + export.AddressOfNames as usize;
            let eot = self.buffer.as_ptr() as usize + export.AddressOfNameOrdinals as usize;
            let eat = self.buffer.as_ptr() as usize + export.AddressOfFunctions as usize;

            let mut allexports:HashMap<String,usize> = HashMap::new();

            for i in 0..export.NumberOfNames{

                let funcnameoffset = unsafe{std::ptr::read((ent+(i*4) as usize) as *const u32)};
                let funcname = ReadStringFromMemory(unsafe{GetCurrentProcess()},(self.buffer.as_ptr() as usize+(funcnameoffset as usize))as *const c_void);


                let ordinaloffset = unsafe{std::ptr::read((eot+(i*2) as usize) as *const u16)};

                let addressoffset = unsafe{std::ptr::read((eat+(ordinaloffset*4) as usize) as *const u32)};

                allexports.insert(funcname,addressoffset as usize);

            }

            Ok(allexports)

        }


    }


    pub fn get_syscallstub(&self,funcname:&str) -> Result<[u8;23],String>{

        let exports =  self.get_exports().unwrap();

        for (funcname1,addr) in exports.iter(){
            if funcname1.to_lowercase()==funcname.to_lowercase(){

                let buffer = unsafe{std::ptr::read((self.buffer.as_ptr() as usize+addr) as *const [u8;23])};
                return Ok(buffer)
            }

        }
        return Err("cannot find the function inside the file exports".to_string());

    }

    pub fn rvatofileoffset(&self, rva:usize) -> Result<usize,String>{
        let sections = self.get_sections();
        
        for i in 0..sections.len(){
            if sections[i].VirtualAddress as usize<= rva && rva<= (sections[i].VirtualAddress as usize+unsafe{*sections[i].Misc.VirtualSize() as usize}){
                let diff = rva - sections[i].VirtualAddress as usize;
                return Ok(sections[i].PointerToRawData as usize+ diff);
            }
        }

        Err(format!("cannot find rva in the sections"))

    }


}


