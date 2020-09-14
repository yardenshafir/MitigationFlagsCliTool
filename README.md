# MitigationFlagsCliTool
Prints mitigation policy information for processes in a dump file.

Usage:
```
-d [dump file] - specify dump file
-l - query current machine (must run elevated)
-k [target machine information] - live kernel debugging (Example: -k net:port:50000,key:1.1.1.1,target:1.2.3.4)
-e - Only print enabled mitigations for process
-m [mitigation,mitigation,...] - Only print processes where any of the requested mitigations are enabled
-ma [mitigation,mitigation,...] - Only print processes where all of the requested mitigations are enabled
```

Usage example:
```
MitigationFlagsCliTool.exe -d c:\temp\live3.dmp -ma DisallowWin32kSystemCalls -e
```

Will show all processes that have the DisallowWin32kSystemCalls mitigation enabled:
```
Current process name: MsMpEngCP.exe, pid: 2352
        Mitigation Flags:
                ControlFlowGuardEnabled
                DisallowStrippedImages
                ForceRelocateImages
                HighEntropyASLREnabled
                ExtensionPointDisable
                DisallowWin32kSystemCalls
                AuditDisallowWin32kSystemCalls
                DisableNonSystemFonts
                PreferSystem32Images
                ProhibitRemoteImageMap
                ProhibitLowILImageMap
                SignatureMitigationOptIn
Current process name: vmwp.exe, pid: 4388
        Mitigation Flags:
                ControlFlowGuardEnabled
                ControlFlowGuardExportSuppressionEnabled
                ControlFlowGuardStrict
                DisallowStrippedImages
                ForceRelocateImages
                HighEntropyASLREnabled
                ExtensionPointDisable
                DisableDynamicCode
                AuditDisableDynamicCode
                DisallowWin32kSystemCalls
                AuditDisallowWin32kSystemCalls
                DisableNonSystemFonts
                PreferSystem32Images
                ProhibitRemoteImageMap
                ProhibitLowILImageMap
                SignatureMitigationOptIn
Current process name: vmmem, pid: 1948
        Mitigation Flags:
                HighEntropyASLREnabled
                DisallowWin32kSystemCalls
                AuditDisallowWin32kSystemCalls
                PreferSystem32Images
                ProhibitRemoteImageMap
                ProhibitLowILImageMap
```
