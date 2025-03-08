# AMSI-Bypass-HWBP

- It's a small debugger that creates new powershell.exe or attach to existing powershell and sets hardware breakpoint at AmsiScanBuffer() address.
- We then change the 3rd parameter which is length stored in R8 register to 1
- This makes AmsiScanBuffer() to scan only 1 byte of buffer (our commands) which will obviously results in AMSI_RESULT_CLEAN


  
