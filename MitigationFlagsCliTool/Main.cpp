#include <Windows.h>
#include <DbgEng.h>
#include <stdio.h>
#include <iostream>
#include <winternl.h>
#include <shlwapi.h>

#undef KERNEL_DEBUG 0

std::string mitigationFlagsNames[64] = {
    "ControlFlowGuardEnabled",
    "ControlFlowGuardExportSuppressionEnabled",
    "ControlFlowGuardStrict",
    "DisallowStrippedImages",
    "ForceRelocateImages",
    "HighEntropyASLREnabled",
    "StackRandomizationDisabled",
    "ExtensionPointDisable",
    "DisableDynamicCode",
    "DisableDynamicCodeAllowOptOut",
    "DisableDynamicCodeAllowRemoteDowngrade",
    "AuditDisableDynamicCode",
    "DisallowWin32kSystemCalls",
    "AuditDisallowWin32kSystemCalls",
    "EnableFilteredWin32kAPIs",
    "AuditFilteredWin32kAPIs",
    "DisableNonSystemFonts",
    "AuditNonSystemFontLoading",
    "PreferSystem32Images",
    "ProhibitRemoteImageMap",
    "AuditProhibitRemoteImageMap",
    "ProhibitLowILImageMap",
    "AuditProhibitLowILImageMap",
    "SignatureMitigationOptIn",
    "AuditBlockNonMicrosoftBinaries",
    "AuditBlockNonMicrosoftBinariesAllowStore",
    "LoaderIntegrityContinuityEnabled",
    "AuditLoaderIntegrityContinuity",
    "EnableModuleTamperingProtection",
    "EnableModuleTamperingProtectionNoInherit",
    "RestrictIndirectBranchPrediction",
    "IsolateSecurityDomain",
    "EnableExportAddressFilter",
    "AuditExportAddressFilter",
    "EnableExportAddressFilterPlus",
    "AuditExportAddressFilterPlus",
    "EnableRopStackPivot",
    "AuditRopStackPivot",
    "EnableRopCallerCheck",
    "AuditRopCallerCheck",
    "EnableRopSimExec",
    "AuditRopSimExec",
    "EnableImportAddressFilter",
    "AuditImportAddressFilter",
    "DisablePageCombine",
    "SpeculativeStoreBypassDisable",
    "CetUserShadowStacks",
    "AuditCetUserShadowStacks",
    "AuditCetUserShadowStacksLogged",
    "UserCetSetContextIpValidation",
    "AuditUserCetSetContextIpValidation",
    "AuditUserCetSetContextIpValidationLogged",
    "CetUserShadowStacksStrictMode",
    "BlockNonCetBinaries",
    "BlockNonCetBinariesNonEhcont",
    "AuditBlockNonCetBinaries",
    "AuditBlockNonCetBinariesLogged",
    "XtendedControlFlowGuard",
    "AuditXtendedControlFlowGuard",
    "PointerAuthUserIp",
    "AuditPointerAuthUserIp",
    "AuditPointerAuthUserIpLogged",
    "CetDynamicApisOutOfProcOnly",
    "UserCetSetContextIpValidationRelaxedMode",
};

typedef
NTSTATUS
(__stdcall*
NtSystemDebugControl) (
    ULONG ControlCode,
    PVOID InputBuffer,
    ULONG InputBufferLength,
    PVOID OutputBuffer,
    ULONG OutputBufferLength,
    PULONG ReturnLength
);

typedef union _SYSDBG_LIVEDUMP_CONTROL_FLAGS
{
    struct
    {
        ULONG UseDumpStorageStack : 1;
        ULONG CompressMemoryPagesData : 1;
        ULONG IncludeUserSpaceMemoryPages : 1;
        ULONG Reserved : 29;
    };
    ULONG AsUlong;
} SYSDBG_LIVEDUMP_CONTROL_FLAGS;

typedef union _SYSDBG_LIVEDUMP_CONTROL_ADDPAGES
{
    struct
    {
        ULONG HypervisorPages : 1;
        ULONG Reserved : 31;
    };
    ULONG AsUlong;
} SYSDBG_LIVEDUMP_CONTROL_ADDPAGES;

typedef struct _SYSDBG_LIVEDUMP_CONTROL
{
    ULONG Version;
    ULONG BugCheckCode;
    ULONG_PTR BugCheckParam1;
    ULONG_PTR BugCheckParam2;
    ULONG_PTR BugCheckParam3;
    ULONG_PTR BugCheckParam4;
    PVOID DumpFileHandle;
    PVOID CancelEventHandle;
    SYSDBG_LIVEDUMP_CONTROL_FLAGS Flags;
    SYSDBG_LIVEDUMP_CONTROL_ADDPAGES AddPagesControl;
} SYSDBG_LIVEDUMP_CONTROL, * PSYSDBG_LIVEDUMP_CONTROL;

#define CONTROL_KERNEL_DUMP 37
static NtSystemDebugControl g_NtSystemDebugControl = NULL;

/*
    Enables or disables the chosen privilege for the current process.
    Taken from here: https://github.com/lilhoser/livedump
*/
BOOL
EnablePrivilege(
    _In_ PCWSTR PrivilegeName,
    _In_ BOOLEAN Acquire
)
{
    HANDLE tokenHandle;
    BOOL ret;
    ULONG tokenPrivilegesSize = FIELD_OFFSET(TOKEN_PRIVILEGES, Privileges[1]);
    PTOKEN_PRIVILEGES tokenPrivileges = static_cast<PTOKEN_PRIVILEGES>(calloc(1, tokenPrivilegesSize));

    if (tokenPrivileges == NULL)
    {
        return FALSE;
    }

    tokenHandle = NULL;
    tokenPrivileges->PrivilegeCount = 1;
    ret = LookupPrivilegeValue(NULL,
        PrivilegeName,
        &tokenPrivileges->Privileges[0].Luid);
    if (ret == FALSE)
    {
        goto Exit;
    }

    tokenPrivileges->Privileges[0].Attributes = Acquire ? SE_PRIVILEGE_ENABLED
        : SE_PRIVILEGE_REMOVED;

    ret = OpenProcessToken(GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES,
        &tokenHandle);
    if (ret == FALSE)
    {
        goto Exit;
    }

    ret = AdjustTokenPrivileges(tokenHandle,
        FALSE,
        tokenPrivileges,
        tokenPrivilegesSize,
        NULL,
        NULL);
    if (ret == FALSE)
    {
        goto Exit;
    }

Exit:
    if (tokenHandle != NULL)
    {
        CloseHandle(tokenHandle);
    }
    free(tokenPrivileges);
    return ret;
}


/*
    Creates a live dump of the current machine.
    Taken from here: https://github.com/lilhoser/livedump
*/
HRESULT
CreateDump (
    _In_ PCSTR FilePath
)
{
    HRESULT result;
    HANDLE handle;
    HMODULE module;
    SYSDBG_LIVEDUMP_CONTROL_FLAGS flags;
    SYSDBG_LIVEDUMP_CONTROL_ADDPAGES pages;
    SYSDBG_LIVEDUMP_CONTROL liveDumpControl;
    NTSTATUS status;
    ULONG returnLength;

    handle = INVALID_HANDLE_VALUE;
    result = S_OK;
    flags.AsUlong = 0;
    pages.AsUlong = 0;

    //
    // Get function addresses
    //
    module = LoadLibrary(L"ntdll.dll");
    if (module == NULL)
    {
        result = S_FALSE;
        goto Exit;
    }

    g_NtSystemDebugControl = (NtSystemDebugControl)
        GetProcAddress(module, "NtSystemDebugControl");

    FreeLibrary(module);

    if (g_NtSystemDebugControl == NULL)
    {
        result = S_FALSE;
        goto Exit;
    }

    //
    // Get SeDebugPrivilege
    //
    if (!EnablePrivilege(SE_DEBUG_NAME, TRUE))
    {
        result = S_FALSE;
        goto Exit;
    }

    //
    // Create the target file (must specify synchronous I/O)
    //
    handle = CreateFileA(FilePath,
        GENERIC_WRITE | GENERIC_READ,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_FLAG_WRITE_THROUGH | FILE_FLAG_NO_BUFFERING,
        NULL);

    if (handle == INVALID_HANDLE_VALUE)
    {
        result = S_FALSE;
        goto Exit;
    }

    //
    // Try to create the requested dump
    //
    memset(&liveDumpControl, 0, sizeof(liveDumpControl));

    //
    // The only thing the kernel looks at in the struct we pass is the handle,
    // the flags and the pages to dump.
    //
    liveDumpControl.DumpFileHandle = (PVOID)(handle);
    liveDumpControl.AddPagesControl = pages;
    liveDumpControl.Flags = flags;

    status = g_NtSystemDebugControl(CONTROL_KERNEL_DUMP,
        (PVOID)(&liveDumpControl),
        sizeof(liveDumpControl),
        NULL,
        0,
        &returnLength);

    if (NT_SUCCESS(status))
    {
        result = S_OK;
    }
    else
    {
        result = S_FALSE;
        goto Exit;
    }

Exit:
    if (handle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(handle);
    }
    return result;
}

BOOLEAN ShouldChooseProcess (
    std::string *Filter,
    ULONG NumberOfFilters,
    ULONG MitigationFlags,
    BOOLEAN FilterByAll
)
{
    ULONG matches = 0;
    if (NumberOfFilters == 0)
    {
        return TRUE;
    }
    else
    {
        for (int f = 0; f < NumberOfFilters; f++)
        {
            for (int i = 0; i < 32; i++)
            {
                if (strcmp(Filter[f].c_str(), mitigationFlagsNames[i].c_str()) == 0)
                {
                    //
                    // Is the mitigation enabled in the process?
                    //
                    if (_bittest64((LONG64*)&MitigationFlags, i))
                    {
                        matches += 1;
                        break;
                    }
                    else if (FilterByAll == TRUE)
                    {
                        //
                        // One of the mitigations we want is not enabled for this process.
                        // We want to filter by all of them so we'll skip this process.
                        //
                        return FALSE;
                    }
                }
            }
        }
    }
    if ((matches == 0) || ((FilterByAll == TRUE) && (matches != NumberOfFilters))) 
    {
        return FALSE;
    }
    return TRUE;
}

void PrintUsage()
{
    printf("Usage:\n\
\t-d [dump file] - specify dump file\n\
\t-l - query current machine (must run elevated)\n\
\t-k [target machine information] - live kernel debugging\n\
\t\tExample: -k net:port:50000,key:1.1.1.1,target:1.2.3.4\n\
\t-e - Only print enabled mitigations for process\n\
\t-m [mitigation,mitigation,...] - Only print processes where any of the requested mitigations are enabled\n\
\t-ma [mitigation,mitigation,...] - Only print processes where all of the requested mitigations are enabled\n");
}

int main(int argc, char* argv[])
{
    IDebugClient* debugClient;
    IDebugSymbols* debugSymbols;
    IDebugDataSpaces* dataSpaces;
    IDebugControl* debugControl;

    HRESULT result;
    ULONG64 kernBase;
    ULONG EPROCESS;
    ULONG SE_AUDIT_PROCESS_CREATION_INFO;
    ULONG64 activeProcessHead;
    ULONG64 process;

    UCHAR imageFileName[15];
    ULONG64 uniquePid;
    LIST_ENTRY activeProcessLinks;
    ULONG mitigationFlags;
    ULONG mitigationFlags2;
    ULONG64 mitigations;
    ULONG64 auditImageFileNamePtr;
    UNICODE_STRING auditImageFileName;
    UNICODE_STRING localImageFileName;
    wchar_t* imageFileNameWide;

    ULONG imageFileNameOffset;
    ULONG uniquePidOffset;
    ULONG activeProcessLinksOffset;
    ULONG mitigationFlagsOffset;
    ULONG mitigationFlags2Offset;
    ULONG seAuditProcessCreationInfoOffset;
    ULONG auditImageFileNameOffset;

    BOOLEAN mitigationEnabled;
    BOOLEAN onlyShowEnabledMitigations;
    std::string filter[64];
    ULONG numberOfFilters;
    BOOLEAN filterByAll;

    PCSTR dumpFilePath = {};
    PCSTR kernelConnectionPath = {};
    BOOLEAN liveDump;
    BOOLEAN kernelConnect;

    onlyShowEnabledMitigations = FALSE;
    numberOfFilters = 0;
    filterByAll = FALSE;
    liveDump = FALSE;
    kernelConnect = FALSE;
    if (argc == 1)
    {
        PrintUsage();
        return 0;
    }
    if (argc > 1)
    {
        for (int i = 0; i < argc; i++)
        {
            if (strcmp(argv[i], "-e") == 0)
            {
                //
                // -e = Only print enabled mitigations for each process
                //
                onlyShowEnabledMitigations = TRUE;
                continue;
            }
            if (strcmp(argv[i], "-m") == 0)
            {
                //
                // -m = Only print processes that any of the chosen mitigations enabled
                //
                if (i + 1 == argc)
                {
                    printf("Flag -m must receive mitigation flags as filters.");
                    return STATUS_INVALID_PARAMETER;
                }
                char* ctx;
                char* mitigation = strtok_s(argv[i + 1], ",", &ctx);
                while (mitigation != NULL)
                {
                    filter[numberOfFilters] = std::string(mitigation);
                    numberOfFilters++;
                    mitigation = strtok_s(NULL, ",", &ctx);
                }
                i++;
                continue;
            }
            if (strcmp(argv[i], "-ma") == 0)
            {
                //
                // -ma = Only print processes that have all the chosen mitigations enabled
                //
                if (i + 1 == argc)
                {
                    printf("Flag -ma must receive mitigation flags as filters.");
                    return STATUS_INVALID_PARAMETER;
                }
                filterByAll = TRUE;
                char* ctx;
                char* mitigation = strtok_s(argv[i + 1], ",", &ctx);
                while (mitigation != NULL)
                {
                    filter[numberOfFilters] = std::string(mitigation);
                    numberOfFilters++;
                    mitigation = strtok_s(NULL, ",", &ctx);
                }
                i++;
                continue;
            }
            if (strcmp(argv[i], "-l") == 0)
            {
                if (dumpFilePath != 0)
                {
                    printf("Both live dump and file dump requested. Conflicting flags.");
                    return STATUS_INVALID_PARAMETER;
                }
                if (kernelConnect == TRUE)
                {
                    printf("Requested both kernel connection and dump file. Conflicting Flags.");
                    return STATUS_INVALID_PARAMETER;
                }
                liveDump = TRUE;
                dumpFilePath = "c:\\temp\\live.dmp";
                printf("Creating a  dump of current machine at path %s\n", dumpFilePath);
                CreateDump(dumpFilePath);
                continue;
            }
            if (strcmp(argv[i], "-d") == 0)
            {
                if (i + 1 == argc)
                {
                    printf("Flag -d must receive a dump file path.");
                    return STATUS_INVALID_PARAMETER;
                }
                if (liveDump == TRUE)
                {
                    printf("Both live dump and file dump requested. Conflicting flags.");
                    return STATUS_INVALID_PARAMETER;
                }
                if (kernelConnect == TRUE)
                {
                    printf("Requested both kernel connection and dump file. Conflicting Flags.");
                    return STATUS_INVALID_PARAMETER;
                }
                dumpFilePath = argv[i + 1];
                i++;
                continue;
            }
            if (strcmp(argv[i], "-k") == 0)
            {
                if (i + 1 == argc)
                {
                    printf("Flag -k must receive connection parameters.");
                    return STATUS_INVALID_PARAMETER;
                }
                if (liveDump == TRUE || dumpFilePath != 0)
                {
                    printf("Requested both kernel connection and dump file. Conflicting Flags.");
                    return STATUS_INVALID_PARAMETER;
                }
                kernelConnect = TRUE;
                kernelConnectionPath = argv[i + 1];
                i++;
                continue;
            }
            if (strcmp(argv[i], "-h") == 0)
            {
                PrintUsage();
                return 0;
            }
        }
    }

    if ((dumpFilePath == 0) && (kernelConnect == FALSE))
    {
        printf("No file path was supplied!\n\
You can use:\n\
\t-d [dump file] - specify dump file\n\
\t-l - query current machine (must run elevated)\n\
\t-k [target machine information] - live kernel debugging\n\
\t\tExample: -k net:port:50000,key:1.1.1.1,target:1.2.3.4\n");
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Initialize interfaces
    //
    debugClient = nullptr;
    debugSymbols = nullptr;
    dataSpaces = nullptr;
    debugControl = nullptr;
    result = DebugCreate(__uuidof(IDebugClient), (PVOID*)&debugClient);
    if (!SUCCEEDED(result))
    {
        printf("DebugCreate failed with error 0x%x\n", result);
        goto Exit;
    }

    result = debugClient->QueryInterface(__uuidof(IDebugSymbols), (PVOID*)&debugSymbols);
    if (!SUCCEEDED(result))
    {
        printf("QueryInterface for debug symbols failed with error 0x%x\n", result);
        goto Exit;
    }

    result = debugClient->QueryInterface(__uuidof(IDebugDataSpaces), (PVOID*)&dataSpaces);
    if (!SUCCEEDED(result))
    {
        printf("QueryInterface for debug data spaces failed with error 0x%x\n", result);
        goto Exit;
    }

    result = debugClient->QueryInterface(__uuidof(IDebugControl), (PVOID*)&debugControl);
    if (!SUCCEEDED(result))
    {
        printf("QueryInterface for debug control failed with error 0x%x\n", result);
        goto Exit;
    }

    if (kernelConnect)
    {
        //
        // Attach to kernel
        //
        result = debugControl->AddEngineOptions(DEBUG_ENGOPT_INITIAL_BREAK);
        if (!SUCCEEDED(result))
        {
            printf("OpenDumpFile failed with error 0x%x\n", result);
            goto Exit;
        }

        result = debugClient->AttachKernel(DEBUG_ATTACH_KERNEL_CONNECTION, kernelConnectionPath);
        if (!SUCCEEDED(result))
        {
            printf("OpenDumpFile failed with error 0x%x\n", result);
            goto Exit;
        }
    }
    else
    {
        //
        // Open the dmp file
        //
        result = debugClient->OpenDumpFile(dumpFilePath);
    }

    //
    // Wait for the file to be loaded with all of its symbols
    //
    result = debugControl->WaitForEvent(DEBUG_WAIT_DEFAULT, INFINITE);
    if (!SUCCEEDED(result))
    {
        printf("WaitForEvent failed with error 0x%x\n", result);
        return result;
    }

    //
    // Get the base of the nt module, we will need it to get other symbols
    //
    result = dataSpaces->ReadDebuggerData(DEBUG_DATA_KernBase,
                                          &kernBase,
                                          sizeof(kernBase),
                                          nullptr);
    if (!SUCCEEDED(result))
    {
        printf("ReadDebuggerData failed with error 0x%x\n", result);
        goto Exit;
    }

    //
    // Get the EPROCESS type
    //
    result = debugSymbols->GetTypeId(kernBase, "_EPROCESS", &EPROCESS);
    if (!SUCCEEDED(result))
    {
        printf("GetTypeId failed with error 0x%x\n", result);
        goto Exit;
    }

    //
    // Get SE_AUDIT_PROCESS_CREATION_INFO type, we'll need it for the filename
    //
    result = debugSymbols->GetTypeId(kernBase,
                                     "_SE_AUDIT_PROCESS_CREATION_INFO",
                                     &SE_AUDIT_PROCESS_CREATION_INFO);
    if (!SUCCEEDED(result))
    {
        printf("GetTypeId failed with error 0x%x\n", result);
        goto Exit;
    }

    //
    // Get the symbol nt!PsActiveProcessHead.
    // We will use it to iterate over all the processes
    //
    result = debugSymbols->GetOffsetByName("nt!PsActiveProcessHead",
                                           &activeProcessHead);
    if (!SUCCEEDED(result))
    {
        printf("GetOffsetByName failed with error 0x%x\n", result);
        goto Exit;
    }

    //
    // Read the LIST_ENTRY in PsActiveProcessHead
    //
    result = dataSpaces->ReadVirtual(activeProcessHead,
                                     &activeProcessLinks,
                                     sizeof(activeProcessLinks),
                                     nullptr);
    if (!SUCCEEDED(result))
    {
        printf("ReadVirtual failed with error 0x%x\n", result);
        goto Exit;
    }

    //
    // Get the offsets of ImageFileName, UniqueProcessId and ActiveProcessLinks
    // fields inside an EPROCESS and the ImageFileName fields in
    // SE_AUDIT_PROCESS_CREATION_INFO
    //
    result = debugSymbols->GetFieldOffset(kernBase,
                                          EPROCESS,
                                          "ImageFileName",
                                          &imageFileNameOffset);
    if (!SUCCEEDED(result))
    {
        printf("GetFieldOffset failed with error 0x%x\n", result);
        goto Exit;
    }
    result = debugSymbols->GetFieldOffset(kernBase,
                                          EPROCESS,
                                          "UniqueProcessId",
                                          &uniquePidOffset);
    if (!SUCCEEDED(result))
    {
        printf("GetFieldOffset failed with error 0x%x\n", result);
        goto Exit;
    }
    result = debugSymbols->GetFieldOffset(kernBase,
                                          EPROCESS,
                                          "ActiveProcessLinks",
                                          &activeProcessLinksOffset);
    if (!SUCCEEDED(result))
    {
        printf("GetFieldOffset failed with error 0x%x\n", result);
        goto Exit;
    }

    result = debugSymbols->GetFieldOffset(kernBase,
                                          EPROCESS,
                                          "MitigationFlags",
                                          &mitigationFlagsOffset);
    if (!SUCCEEDED(result))
    {
        printf("GetFieldOffset failed with error 0x%x\n", result);
        goto Exit;
    }

    result = debugSymbols->GetFieldOffset(kernBase,
                                          EPROCESS,
                                          "MitigationFlags2",
                                          &mitigationFlags2Offset);
    if (!SUCCEEDED(result))
    {
        printf("GetFieldOffset failed with error 0x%x\n", result);
        goto Exit;
    }

    result = debugSymbols->GetFieldOffset(kernBase,
                                          EPROCESS,
                                          "SeAuditProcessCreationInfo",
                                          &seAuditProcessCreationInfoOffset);
    if (!SUCCEEDED(result))
    {
        printf("GetFieldOffset failed with error 0x%x\n", result);
        goto Exit;
    }

    result = debugSymbols->GetFieldOffset(kernBase,
                                          SE_AUDIT_PROCESS_CREATION_INFO,
                                          "ImageFileName",
                                          &auditImageFileNameOffset);
    if (!SUCCEEDED(result))
    {
        printf("GetFieldOffset failed with error 0x%x\n", result);
        goto Exit;
    }

    //
    // Iterate over all processes in a loop, print each process' name and pid
    //
    process = (ULONG64)activeProcessLinks.Flink - activeProcessLinksOffset;
    do
    {
        //
        // SeAuditProcessCreationInfo.ImageFileName is a
        // OBJECT_NAME_INFORMATION which is a documented structure
        // that only contains a UNICODE_STRING.
        // Since it's documented we can count on it to not change.
        //
        result = dataSpaces->ReadVirtual(process + seAuditProcessCreationInfoOffset + auditImageFileNameOffset,
                                         &auditImageFileNamePtr,
                                         sizeof(auditImageFileNamePtr),
                                         nullptr);
        if (!SUCCEEDED(result))
        {
            printf("ReadVirtual failed with error 0x%x\n", result);
            continue;
        }
        result = dataSpaces->ReadVirtual(auditImageFileNamePtr,
                                         &auditImageFileName,
                                         sizeof(auditImageFileName),
                                         nullptr);
        if (!SUCCEEDED(result))
        {
            printf("ReadVirtual failed with error 0x%x\n", result);
            continue;
        }

        //
        // Get process name. First try the name in SeAuditProcessCreationInfo
        // and if that's empty use the one in ImageFileName field.
        // We'll populate a unicode string for the full path of the binary
        // but for now we'll only print the basename.
        //
        imageFileNameWide = { };
        if (auditImageFileName.Length != 0)
        {
            localImageFileName.Length = auditImageFileName.Length;
            localImageFileName.MaximumLength = auditImageFileName.MaximumLength;
            localImageFileName.Buffer = (PWSTR)VirtualAlloc(NULL,
                                                            auditImageFileName.Length,
                                                            MEM_COMMIT,
                                                            PAGE_READWRITE);
            if (localImageFileName.Buffer != NULL)
            {
                result = dataSpaces->ReadVirtual((ULONG64)auditImageFileName.Buffer,
                                                 localImageFileName.Buffer,
                                                 localImageFileName.Length,
                                                 nullptr);
                if (!SUCCEEDED(result))
                {
                    printf("ReadVirtual failed with error 0x%x\n", result);
                    if (localImageFileName.Buffer != NULL)
                    {
                        VirtualFree(localImageFileName.Buffer, NULL, MEM_RELEASE);
                    }
                    continue;
                }
                imageFileNameWide = PathFindFileNameW(localImageFileName.Buffer);
            }
        }
        else
        {
            //
            // auditImageFileName is empty.
            // This usually happens for processes that aren't backed by an
            // image, like System. Use ImageFileName instead.
            //
            result = dataSpaces->ReadVirtual(process + imageFileNameOffset,
                                             &imageFileName,
                                             sizeof(imageFileName),
                                             nullptr);
            if (!SUCCEEDED(result))
            {
                printf("ReadVirtual failed with error 0x%x\n", result);
                continue;
            }
            
            //
            // Get the size of imageFileName
            //
            ULONG neededSize = MultiByteToWideChar(0,
                                                   0,
                                                   (char*)imageFileName,
                                                   -1,
                                                   NULL,
                                                   0);
            imageFileNameWide = (wchar_t*)VirtualAlloc(NULL,
                                                       neededSize,
                                                       MEM_COMMIT,
                                                       PAGE_READWRITE);
            if (imageFileNameWide != NULL)
            {
                //
                // Convert imageFileName to a wide string to use the same format
                // as the one in SeAuditProcessCreationInfo.
                //
                neededSize = MultiByteToWideChar(CP_UTF8,
                                                 0,
                                                 (char*)imageFileName,
                                                 -1,
                                                 imageFileNameWide,
                                                 neededSize);

                //
                // Populate a unicode string for consistency in case we ever
                // use it in the future.
                //
                localImageFileName.Length = (neededSize * 2) - 2;
                localImageFileName.MaximumLength = localImageFileName.Length;
                localImageFileName.Buffer = imageFileNameWide;
            }
        }
        result = dataSpaces->ReadVirtual(process + uniquePidOffset,
                                         &uniquePid,
                                         sizeof(uniquePid),
                                         nullptr);
        if (!SUCCEEDED(result))
        {
            printf("ReadVirtual failed with error 0x%x\n", result);
            continue;
        }
        result = dataSpaces->ReadVirtual(process + activeProcessLinksOffset,
                                         &activeProcessLinks,
                                         sizeof(activeProcessLinks),
                                         nullptr);
        if (!SUCCEEDED(result))
        {
            printf("ReadVirtual failed with error 0x%x\n", result);
            continue;
        }

        result = dataSpaces->ReadVirtual(process + mitigationFlagsOffset,
                                         &mitigationFlags,
                                         sizeof(mitigationFlags),
                                         nullptr);
        if (!SUCCEEDED(result))
        {
            printf("ReadVirtual failed with error 0x%x\n", result);
            continue;
        }

        result = dataSpaces->ReadVirtual(process + mitigationFlags2Offset,
                                         &mitigationFlags2,
                                         sizeof(mitigationFlags2),
                                         nullptr);
        if (!SUCCEEDED(result))
        {
            printf("ReadVirtual failed with error 0x%x\n", result);
            continue;
        }
        mitigations = mitigationFlags + ((ULONG64)mitigationFlags2 << 32);

        //
        // Check if there are any filters set and if the current process
        // passes them and should be printed.
        //
        if (ShouldChooseProcess(filter,
                                numberOfFilters,
                                mitigationFlags,
                                filterByAll) == TRUE)
        {
            printf("Current process name: %ls, pid: %d\n", imageFileNameWide, uniquePid);
            printf("\tMitigation Flags:\n");
            //
            // Print all mitigation flags
            //
            for (int i = 0; i < sizeof(ULONG64) * 8; i++)
            {
                mitigationEnabled = _bittest64((LONG64*)&mitigations, i);
                if (onlyShowEnabledMitigations)
                {
                    if (mitigationEnabled)
                    {
                        printf("\t\t%s\n", mitigationFlagsNames[i].c_str());
                    }
                }
                else
                {
                    printf("\t\t%s = %d\n", mitigationFlagsNames[i].c_str(), mitigationEnabled);
                }
            }
        }
        if (localImageFileName.Buffer != NULL)
        {
            VirtualFree(localImageFileName.Buffer, NULL, MEM_RELEASE);
        }

        //
        // Get the next process from the list and subtract activeProcessLinksOffset
        // to get to the start of the EPROCESS.
        //
        process = (ULONG64)activeProcessLinks.Flink - activeProcessLinksOffset;
    } while ((ULONG64)activeProcessLinks.Flink != activeProcessHead);

Exit:
    if (debugClient != nullptr)
    {
        //
        // End the current session
        //
        debugClient->EndSession(DEBUG_END_ACTIVE_DETACH);
        debugClient->Release();
    }
    if (debugSymbols != nullptr)
    {
        debugSymbols->Release();
    }
    if (dataSpaces != nullptr)
    {
        dataSpaces->Release();
    }
    if (debugControl != nullptr)
    {
        debugControl->Release();
    }
    if (liveDump)
    {
        DeleteFileA(dumpFilePath);
    }
    return 0;
}
