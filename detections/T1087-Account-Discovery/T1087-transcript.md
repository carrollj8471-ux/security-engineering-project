**********************
Windows PowerShell transcript start
Start time: 20260716130434
Username: CORP\Administrator
RunAs User: CORP\Administrator
Configuration Name: 
Machine: WIN11 (Microsoft Windows NT 10.0.26200.0)
Host Application: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Process ID: 2640
PSVersion: 5.1.26100.8655
PSEdition: Desktop
PSCompatibleVersions: 1.0, 2.0, 3.0, 4.0, 5.0, 5.1.26100.8655
BuildVersion: 10.0.26100.8655
CLRVersion: 4.0.30319.42000
WSManStackVersion: 3.0
PSRemotingProtocolVersion: 2.3
SerializationVersion: 1.1.0.1
**********************
Transcript started, output file is C:\Temp\T1087-transcript.txt
PS C:\WINDOWS\system32> Invoke-AtomicTest T1087.001 `
-PathToAtomicsFolder C:\AtomicRedTeam\atomics `
-TestNumbers 8
PathToAtomicsFolder = C:\AtomicRedTeam\atomics
Executing test:
T1087.001-8 Enumerate all accounts on Windows (Local)

User accounts for \\WIN11
-------------------------------------------------------------------------------
Administrator            DefaultAccount           Guest                    
joshc                    WDAGUtilityAccount       win11                    
WsiAccount               
The command completed successfully.
 Volume in drive C has no label.
 Volume Serial Number is 80B7-0E7D
 Directory of c:\Users
07/09/2026  02:43 PM    <DIR>          .
07/14/2026  03:03 PM    <DIR>          Administrator
07/14/2026  03:02 PM    <DIR>          alice.johnson
07/09/2026  05:09 PM    <DIR>          joshc
07/09/2026  03:38 PM    <DIR>          Public
07/09/2026  03:42 PM    <DIR>          win11
07/09/2026  05:01 PM    <DIR>          WsiAccount
               0 File(s)              0 bytes
               7 Dir(s)  32,892,710,912 bytes free
Currently stored credentials:
* NONE *
Alias name     Users
Comment        Users are prevented from making accidental or intentional system-wide changes and can run most applications
Members
-------------------------------------------------------------------------------
CORP\Domain Users
joshc
NT AUTHORITY\Authenticated Users
NT AUTHORITY\INTERACTIVE
win11
WsiAccount
The command completed successfully.
Aliases for \\WIN11
-------------------------------------------------------------------------------
*Access Control Assistance Operators
*Administrators
*Backup Operators
*Cryptographic Operators
*Device Owners
*Distributed COM Users
*Event Log Readers
*Guests
*Hyper-V Administrators
*IIS_IUSRS
*Network Configuration Operators
*OpenSSH Users
*Performance Log Users
*Performance Monitor Users
*Power Users
*Remote Desktop Users
*Remote Management Users
*Replicator
*System Managed Accounts Group
*User Mode Hardware Operators
*Users
The command completed successfully.
Exit code: 0
Done executing test:
T1087.001-8 Enumerate all accounts on Windows (Local)

PS C:\WINDOWS\system32> Invoke-AtomicTest T1087.001 `
-PathToAtomicsFolder C:\AtomicRedTeam\atomics `
-TestNumbers 8, 9, 10, 11
PathToAtomicsFolder = C:\AtomicRedTeam\atomics
Executing test:
T1087.001-8 Enumerate all accounts on Windows (Local)

User accounts for \\WIN11
-------------------------------------------------------------------------------
Administrator            DefaultAccount           Guest                    
joshc                    WDAGUtilityAccount       win11                    
WsiAccount               
The command completed successfully.
 Volume in drive C has no label.
 Volume Serial Number is 80B7-0E7D
 Directory of c:\Users
07/09/2026  02:43 PM    <DIR>          .
07/14/2026  03:03 PM    <DIR>          Administrator
07/14/2026  03:02 PM    <DIR>          alice.johnson
07/09/2026  05:09 PM    <DIR>          joshc
07/09/2026  03:38 PM    <DIR>          Public
07/09/2026  03:42 PM    <DIR>          win11
07/09/2026  05:01 PM    <DIR>          WsiAccount
               0 File(s)              0 bytes
               7 Dir(s)  33,138,323,456 bytes free
Currently stored credentials:
* NONE *
Alias name     Users
Comment        Users are prevented from making accidental or intentional system-wide changes and can run most applications
Members
-------------------------------------------------------------------------------
CORP\Domain Users
joshc
NT AUTHORITY\Authenticated Users
NT AUTHORITY\INTERACTIVE
win11
WsiAccount
The command completed successfully.
Aliases for \\WIN11
-------------------------------------------------------------------------------
*Access Control Assistance Operators
*Administrators
*Backup Operators
*Cryptographic Operators
*Device Owners
*Distributed COM Users
*Event Log Readers
*Guests
*Hyper-V Administrators
*IIS_IUSRS
*Network Configuration Operators
*OpenSSH Users
*Performance Log Users
*Performance Monitor Users
*Power Users
*Remote Desktop Users
*Remote Management Users
*Replicator
*System Managed Accounts Group
*User Mode Hardware Operators
*Users
The command completed successfully.
Exit code: 0
Done executing test:
T1087.001-8 Enumerate all accounts on Windows (Local)

Executing test:
T1087.001-9 Enumerate all accounts via PowerShell (Local)

User accounts for \\WIN11
-------------------------------------------------------------------------------
Administrator            DefaultAccount           Guest                    
joshc                    WDAGUtilityAccount       win11                    
WsiAccount               
The command completed successfully.
Currently stored credentials:
* NONE *
Name               Enabled Description                                                                                 
----               ------- -----------                                                                                 
Administrator      False   Built-in account for administering the computer/domain                                      
DefaultAccount     False   A user account managed by the system.                                                       
Guest              False   Built-in account for guest access to the computer/domain                                    
joshc              True                                                                                                
WDAGUtilityAccount False   A user account managed and used by the system for Windows Defender Application Guard scen...
win11              True                                                                                                
WsiAccount         False   A user account managed and used by the system for Web Sign-in scenarios.                    
Name            : CORP\Domain Users
SID             : S-1-5-21-615428073-717688660-1076213546-513
PrincipalSource : ActiveDirectory
ObjectClass     : Group
Name            : NT AUTHORITY\Authenticated Users
SID             : S-1-5-11
PrincipalSource : Unknown
ObjectClass     : Group
Name            : NT AUTHORITY\INTERACTIVE
SID             : S-1-5-4
PrincipalSource : Unknown
ObjectClass     : Group
Name            : WIN11\joshc
SID             : S-1-5-21-3176583864-1572492899-649689161-1002
PrincipalSource : MicrosoftAccount
ObjectClass     : User
Name            : WIN11\win11
SID             : S-1-5-21-3176583864-1572492899-649689161-1001
PrincipalSource : MicrosoftAccount
ObjectClass     : User
Name            : WIN11\WsiAccount
SID             : S-1-5-21-3176583864-1572492899-649689161-1003
PrincipalSource : Local
ObjectClass     : User
PSPath            : Microsoft.PowerShell.Core\FileSystem::C:\Users\Administrator
PSParentPath      : Microsoft.PowerShell.Core\FileSystem::C:\Users
PSChildName       : Administrator
PSDrive           : C
PSProvider        : Microsoft.PowerShell.Core\FileSystem
PSIsContainer     : True
Name              : Administrator
FullName          : C:\Users\Administrator
Parent            : Users
Exists            : True
Root              : C:\
Extension         : 
CreationTime      : 7/9/2026 2:43:40 PM
CreationTimeUtc   : 7/9/2026 6:43:40 PM
LastAccessTime    : 7/16/2026 1:04:59 PM
LastAccessTimeUtc : 7/16/2026 5:04:59 PM
LastWriteTime     : 7/14/2026 3:03:44 PM
LastWriteTimeUtc  : 7/14/2026 7:03:44 PM
Attributes        : Directory
Mode              : d-----
BaseName          : Administrator
Target            : {}
LinkType          : 
PSPath            : Microsoft.PowerShell.Core\FileSystem::C:\Users\alice.johnson
PSParentPath      : Microsoft.PowerShell.Core\FileSystem::C:\Users
PSChildName       : alice.johnson
PSDrive           : C
PSProvider        : Microsoft.PowerShell.Core\FileSystem
PSIsContainer     : True
Name              : alice.johnson
FullName          : C:\Users\alice.johnson
Parent            : Users
Exists            : True
Root              : C:\
Extension         : .johnson
CreationTime      : 7/9/2026 2:11:59 PM
CreationTimeUtc   : 7/9/2026 6:11:59 PM
LastAccessTime    : 7/16/2026 12:44:10 PM
LastAccessTimeUtc : 7/16/2026 4:44:10 PM
LastWriteTime     : 7/14/2026 3:02:55 PM
LastWriteTimeUtc  : 7/14/2026 7:02:55 PM
Attributes        : Directory
Mode              : d-----
BaseName          : alice.johnson
Target            : {}
LinkType          : 
PSPath            : Microsoft.PowerShell.Core\FileSystem::C:\Users\joshc
PSParentPath      : Microsoft.PowerShell.Core\FileSystem::C:\Users
PSChildName       : joshc
PSDrive           : C
PSProvider        : Microsoft.PowerShell.Core\FileSystem
PSIsContainer     : True
Name              : joshc
FullName          : C:\Users\joshc
Parent            : Users
Exists            : True
Root              : C:\
Extension         : 
CreationTime      : 7/9/2026 5:01:55 PM
CreationTimeUtc   : 7/9/2026 9:01:55 PM
LastAccessTime    : 7/16/2026 12:44:36 PM
LastAccessTimeUtc : 7/16/2026 4:44:36 PM
LastWriteTime     : 7/9/2026 5:09:00 PM
LastWriteTimeUtc  : 7/9/2026 9:09:00 PM
Attributes        : Directory
Mode              : d-----
BaseName          : joshc
Target            : {}
LinkType          : 
PSPath            : Microsoft.PowerShell.Core\FileSystem::C:\Users\Public
PSParentPath      : Microsoft.PowerShell.Core\FileSystem::C:\Users
PSChildName       : Public
PSDrive           : C
PSProvider        : Microsoft.PowerShell.Core\FileSystem
PSIsContainer     : True
Name              : Public
FullName          : C:\Users\Public
Parent            : Users
Exists            : True
Root              : C:\
Extension         : 
CreationTime      : 4/1/2024 3:26:06 AM
CreationTimeUtc   : 4/1/2024 7:26:06 AM
LastAccessTime    : 7/16/2026 12:44:10 PM
LastAccessTimeUtc : 7/16/2026 4:44:10 PM
LastWriteTime     : 7/9/2026 3:38:16 PM
LastWriteTimeUtc  : 7/9/2026 7:38:16 PM
Attributes        : ReadOnly, Directory
Mode              : d-r---
BaseName          : Public
Target            : {}
LinkType          : 
PSPath            : Microsoft.PowerShell.Core\FileSystem::C:\Users\win11
PSParentPath      : Microsoft.PowerShell.Core\FileSystem::C:\Users
PSChildName       : win11
PSDrive           : C
PSProvider        : Microsoft.PowerShell.Core\FileSystem
PSIsContainer     : True
Name              : win11
FullName          : C:\Users\win11
Parent            : Users
Exists            : True
Root              : C:\
Extension         : 
CreationTime      : 7/9/2026 3:36:26 PM
CreationTimeUtc   : 7/9/2026 7:36:26 PM
LastAccessTime    : 7/16/2026 12:44:36 PM
LastAccessTimeUtc : 7/16/2026 4:44:36 PM
LastWriteTime     : 7/9/2026 3:42:04 PM
LastWriteTimeUtc  : 7/9/2026 7:42:04 PM
Attributes        : Directory
Mode              : d-----
BaseName          : win11
Target            : {}
LinkType          : 
PSPath            : Microsoft.PowerShell.Core\FileSystem::C:\Users\WsiAccount
PSParentPath      : Microsoft.PowerShell.Core\FileSystem::C:\Users
PSChildName       : WsiAccount
PSDrive           : C
PSProvider        : Microsoft.PowerShell.Core\FileSystem
PSIsContainer     : True
Name              : WsiAccount
FullName          : C:\Users\WsiAccount
Parent            : Users
Exists            : True
Root              : C:\
Extension         : 
CreationTime      : 7/9/2026 5:01:23 PM
CreationTimeUtc   : 7/9/2026 9:01:23 PM
LastAccessTime    : 7/16/2026 12:44:36 PM
LastAccessTimeUtc : 7/16/2026 4:44:36 PM
LastWriteTime     : 7/9/2026 5:01:24 PM
LastWriteTimeUtc  : 7/9/2026 9:01:24 PM
Attributes        : Directory
Mode              : d-----
BaseName          : WsiAccount
Target            : {}
LinkType          : 
PSPath            : Microsoft.PowerShell.Core\FileSystem::C:\Users\Administrator
PSParentPath      : Microsoft.PowerShell.Core\FileSystem::C:\Users
PSChildName       : Administrator
PSDrive           : C
PSProvider        : Microsoft.PowerShell.Core\FileSystem
PSIsContainer     : True
Name              : Administrator
FullName          : C:\Users\Administrator
Parent            : Users
Exists            : True
Root              : C:\
Extension         : 
CreationTime      : 7/9/2026 2:43:40 PM
CreationTimeUtc   : 7/9/2026 6:43:40 PM
LastAccessTime    : 7/16/2026 1:04:59 PM
LastAccessTimeUtc : 7/16/2026 5:04:59 PM
LastWriteTime     : 7/14/2026 3:03:44 PM
LastWriteTimeUtc  : 7/14/2026 7:03:44 PM
Attributes        : Directory
Mode              : d-----
BaseName          : Administrator
Target            : {}
LinkType          : 
PSPath            : Microsoft.PowerShell.Core\FileSystem::C:\Users\alice.johnson
PSParentPath      : Microsoft.PowerShell.Core\FileSystem::C:\Users
PSChildName       : alice.johnson
PSDrive           : C
PSProvider        : Microsoft.PowerShell.Core\FileSystem
PSIsContainer     : True
Name              : alice.johnson
FullName          : C:\Users\alice.johnson
Parent            : Users
Exists            : True
Root              : C:\
Extension         : .johnson
CreationTime      : 7/9/2026 2:11:59 PM
CreationTimeUtc   : 7/9/2026 6:11:59 PM
LastAccessTime    : 7/16/2026 12:44:10 PM
LastAccessTimeUtc : 7/16/2026 4:44:10 PM
LastWriteTime     : 7/14/2026 3:02:55 PM
LastWriteTimeUtc  : 7/14/2026 7:02:55 PM
Attributes        : Directory
Mode              : d-----
BaseName          : alice.johnson
Target            : {}
LinkType          : 
PSPath            : Microsoft.PowerShell.Core\FileSystem::C:\Users\joshc
PSParentPath      : Microsoft.PowerShell.Core\FileSystem::C:\Users
PSChildName       : joshc
PSDrive           : C
PSProvider        : Microsoft.PowerShell.Core\FileSystem
PSIsContainer     : True
Name              : joshc
FullName          : C:\Users\joshc
Parent            : Users
Exists            : True
Root              : C:\
Extension         : 
CreationTime      : 7/9/2026 5:01:55 PM
CreationTimeUtc   : 7/9/2026 9:01:55 PM
LastAccessTime    : 7/16/2026 12:44:36 PM
LastAccessTimeUtc : 7/16/2026 4:44:36 PM
LastWriteTime     : 7/9/2026 5:09:00 PM
LastWriteTimeUtc  : 7/9/2026 9:09:00 PM
Attributes        : Directory
Mode              : d-----
BaseName          : joshc
Target            : {}
LinkType          : 
PSPath            : Microsoft.PowerShell.Core\FileSystem::C:\Users\Public
PSParentPath      : Microsoft.PowerShell.Core\FileSystem::C:\Users
PSChildName       : Public
PSDrive           : C
PSProvider        : Microsoft.PowerShell.Core\FileSystem
PSIsContainer     : True
Name              : Public
FullName          : C:\Users\Public
Parent            : Users
Exists            : True
Root              : C:\
Extension         : 
CreationTime      : 4/1/2024 3:26:06 AM
CreationTimeUtc   : 4/1/2024 7:26:06 AM
LastAccessTime    : 7/16/2026 12:44:10 PM
LastAccessTimeUtc : 7/16/2026 4:44:10 PM
LastWriteTime     : 7/9/2026 3:38:16 PM
LastWriteTimeUtc  : 7/9/2026 7:38:16 PM
Attributes        : ReadOnly, Directory
Mode              : d-r---
BaseName          : Public
Target            : {}
LinkType          : 
PSPath            : Microsoft.PowerShell.Core\FileSystem::C:\Users\win11
PSParentPath      : Microsoft.PowerShell.Core\FileSystem::C:\Users
PSChildName       : win11
PSDrive           : C
PSProvider        : Microsoft.PowerShell.Core\FileSystem
PSIsContainer     : True
Name              : win11
FullName          : C:\Users\win11
Parent            : Users
Exists            : True
Root              : C:\
Extension         : 
CreationTime      : 7/9/2026 3:36:26 PM
CreationTimeUtc   : 7/9/2026 7:36:26 PM
LastAccessTime    : 7/16/2026 12:44:36 PM
LastAccessTimeUtc : 7/16/2026 4:44:36 PM
LastWriteTime     : 7/9/2026 3:42:04 PM
LastWriteTimeUtc  : 7/9/2026 7:42:04 PM
Attributes        : Directory
Mode              : d-----
BaseName          : win11
Target            : {}
LinkType          : 
PSPath            : Microsoft.PowerShell.Core\FileSystem::C:\Users\WsiAccount
PSParentPath      : Microsoft.PowerShell.Core\FileSystem::C:\Users
PSChildName       : WsiAccount
PSDrive           : C
PSProvider        : Microsoft.PowerShell.Core\FileSystem
PSIsContainer     : True
Name              : WsiAccount
FullName          : C:\Users\WsiAccount
Parent            : Users
Exists            : True
Root              : C:\
Extension         : 
CreationTime      : 7/9/2026 5:01:23 PM
CreationTimeUtc   : 7/9/2026 9:01:23 PM
LastAccessTime    : 7/16/2026 12:44:36 PM
LastAccessTimeUtc : 7/16/2026 4:44:36 PM
LastWriteTime     : 7/9/2026 5:01:24 PM
LastWriteTimeUtc  : 7/9/2026 9:01:24 PM
Attributes        : Directory
Mode              : d-----
BaseName          : WsiAccount
Target            : {}
LinkType          : 
PSPath            : Microsoft.PowerShell.Core\FileSystem::C:\Users\Administrator
PSParentPath      : Microsoft.PowerShell.Core\FileSystem::C:\Users
PSChildName       : Administrator
PSDrive           : C
PSProvider        : Microsoft.PowerShell.Core\FileSystem
PSIsContainer     : True
Name              : Administrator
FullName          : C:\Users\Administrator
Parent            : Users
Exists            : True
Root              : C:\
Extension         : 
CreationTime      : 7/9/2026 2:43:40 PM
CreationTimeUtc   : 7/9/2026 6:43:40 PM
LastAccessTime    : 7/16/2026 1:04:59 PM
LastAccessTimeUtc : 7/16/2026 5:04:59 PM
LastWriteTime     : 7/14/2026 3:03:44 PM
LastWriteTimeUtc  : 7/14/2026 7:03:44 PM
Attributes        : Directory
Mode              : d-----
BaseName          : Administrator
Target            : {}
LinkType          : 
PSPath            : Microsoft.PowerShell.Core\FileSystem::C:\Users\alice.johnson
PSParentPath      : Microsoft.PowerShell.Core\FileSystem::C:\Users
PSChildName       : alice.johnson
PSDrive           : C
PSProvider        : Microsoft.PowerShell.Core\FileSystem
PSIsContainer     : True
Name              : alice.johnson
FullName          : C:\Users\alice.johnson
Parent            : Users
Exists            : True
Root              : C:\
Extension         : .johnson
CreationTime      : 7/9/2026 2:11:59 PM
CreationTimeUtc   : 7/9/2026 6:11:59 PM
LastAccessTime    : 7/16/2026 12:44:10 PM
LastAccessTimeUtc : 7/16/2026 4:44:10 PM
LastWriteTime     : 7/14/2026 3:02:55 PM
LastWriteTimeUtc  : 7/14/2026 7:02:55 PM
Attributes        : Directory
Mode              : d-----
BaseName          : alice.johnson
Target            : {}
LinkType          : 
PSPath            : Microsoft.PowerShell.Core\FileSystem::C:\Users\joshc
PSParentPath      : Microsoft.PowerShell.Core\FileSystem::C:\Users
PSChildName       : joshc
PSDrive           : C
PSProvider        : Microsoft.PowerShell.Core\FileSystem
PSIsContainer     : True
Name              : joshc
FullName          : C:\Users\joshc
Parent            : Users
Exists            : True
Root              : C:\
Extension         : 
CreationTime      : 7/9/2026 5:01:55 PM
CreationTimeUtc   : 7/9/2026 9:01:55 PM
LastAccessTime    : 7/16/2026 12:44:36 PM
LastAccessTimeUtc : 7/16/2026 4:44:36 PM
LastWriteTime     : 7/9/2026 5:09:00 PM
LastWriteTimeUtc  : 7/9/2026 9:09:00 PM
Attributes        : Directory
Mode              : d-----
BaseName          : joshc
Target            : {}
LinkType          : 
PSPath            : Microsoft.PowerShell.Core\FileSystem::C:\Users\Public
PSParentPath      : Microsoft.PowerShell.Core\FileSystem::C:\Users
PSChildName       : Public
PSDrive           : C
PSProvider        : Microsoft.PowerShell.Core\FileSystem
PSIsContainer     : True
Name              : Public
FullName          : C:\Users\Public
Parent            : Users
Exists            : True
Root              : C:\
Extension         : 
CreationTime      : 4/1/2024 3:26:06 AM
CreationTimeUtc   : 4/1/2024 7:26:06 AM
LastAccessTime    : 7/16/2026 12:44:10 PM
LastAccessTimeUtc : 7/16/2026 4:44:10 PM
LastWriteTime     : 7/9/2026 3:38:16 PM
LastWriteTimeUtc  : 7/9/2026 7:38:16 PM
Attributes        : ReadOnly, Directory
Mode              : d-r---
BaseName          : Public
Target            : {}
LinkType          : 
PSPath            : Microsoft.PowerShell.Core\FileSystem::C:\Users\win11
PSParentPath      : Microsoft.PowerShell.Core\FileSystem::C:\Users
PSChildName       : win11
PSDrive           : C
PSProvider        : Microsoft.PowerShell.Core\FileSystem
PSIsContainer     : True
Name              : win11
FullName          : C:\Users\win11
Parent            : Users
Exists            : True
Root              : C:\
Extension         : 
CreationTime      : 7/9/2026 3:36:26 PM
CreationTimeUtc   : 7/9/2026 7:36:26 PM
LastAccessTime    : 7/16/2026 12:44:36 PM
LastAccessTimeUtc : 7/16/2026 4:44:36 PM
LastWriteTime     : 7/9/2026 3:42:04 PM
LastWriteTimeUtc  : 7/9/2026 7:42:04 PM
Attributes        : Directory
Mode              : d-----
BaseName          : win11
Target            : {}
LinkType          : 
PSPath            : Microsoft.PowerShell.Core\FileSystem::C:\Users\WsiAccount
PSParentPath      : Microsoft.PowerShell.Core\FileSystem::C:\Users
PSChildName       : WsiAccount
PSDrive           : C
PSProvider        : Microsoft.PowerShell.Core\FileSystem
PSIsContainer     : True
Name              : WsiAccount
FullName          : C:\Users\WsiAccount
Parent            : Users
Exists            : True
Root              : C:\
Extension         : 
CreationTime      : 7/9/2026 5:01:23 PM
CreationTimeUtc   : 7/9/2026 9:01:23 PM
LastAccessTime    : 7/16/2026 12:44:36 PM
LastAccessTimeUtc : 7/16/2026 4:44:36 PM
LastWriteTime     : 7/9/2026 5:01:24 PM
LastWriteTimeUtc  : 7/9/2026 9:01:24 PM
Attributes        : Directory
Mode              : d-----
BaseName          : WsiAccount
Target            : {}
LinkType          : 
Description     : Members of this group can remotely query authorization attributes and permissions for resources on 
                  this computer.
Name            : Access Control Assistance Operators
SID             : S-1-5-32-579
PrincipalSource : Local
ObjectClass     : Group
Description     : Administrators have complete and unrestricted access to the computer/domain
Name            : Administrators
SID             : S-1-5-32-544
PrincipalSource : Local
ObjectClass     : Group
Description     : Backup Operators can override security restrictions for the sole purpose of backing up or restoring 
                  files
Name            : Backup Operators
SID             : S-1-5-32-551
PrincipalSource : Local
ObjectClass     : Group
Description     : Members are authorized to perform cryptographic operations.
Name            : Cryptographic Operators
SID             : S-1-5-32-569
PrincipalSource : Local
ObjectClass     : Group
Description     : Members of this group can change system-wide settings.
Name            : Device Owners
SID             : S-1-5-32-583
PrincipalSource : Local
ObjectClass     : Group
Description     : Members are allowed to launch, activate and use Distributed COM objects on this machine.
Name            : Distributed COM Users
SID             : S-1-5-32-562
PrincipalSource : Local
ObjectClass     : Group
Description     : Members of this group can read event logs from local machine
Name            : Event Log Readers
SID             : S-1-5-32-573
PrincipalSource : Local
ObjectClass     : Group
Description     : Guests have the same access as members of the Users group by default, except for the Guest account 
                  which is further restricted
Name            : Guests
SID             : S-1-5-32-546
PrincipalSource : Local
ObjectClass     : Group
Description     : Members of this group have complete and unrestricted access to all features of Hyper-V.
Name            : Hyper-V Administrators
SID             : S-1-5-32-578
PrincipalSource : Local
ObjectClass     : Group
Description     : Built-in group used by Internet Information Services.
Name            : IIS_IUSRS
SID             : S-1-5-32-568
PrincipalSource : Local
ObjectClass     : Group
Description     : Members in this group can have some administrative privileges to manage configuration of networking 
                  features
Name            : Network Configuration Operators
SID             : S-1-5-32-556
PrincipalSource : Local
ObjectClass     : Group
Description     : Members of this group may connect to this computer using SSH.
Name            : OpenSSH Users
SID             : S-1-5-32-585
PrincipalSource : Local
ObjectClass     : Group
Description     : Members of this group may schedule logging of performance counters, enable trace providers, and 
                  collect event traces both locally and via remote access to this computer
Name            : Performance Log Users
SID             : S-1-5-32-559
PrincipalSource : Local
ObjectClass     : Group
Description     : Members of this group can access performance counter data locally and remotely
Name            : Performance Monitor Users
SID             : S-1-5-32-558
PrincipalSource : Local
ObjectClass     : Group
Description     : Power Users are included for backwards compatibility and possess limited administrative powers
Name            : Power Users
SID             : S-1-5-32-547
PrincipalSource : Local
ObjectClass     : Group
Description     : Members in this group are granted the right to logon remotely
Name            : Remote Desktop Users
SID             : S-1-5-32-555
PrincipalSource : Local
ObjectClass     : Group
Description     : Members of this group can access WMI resources over management protocols (such as WS-Management via 
                  the Windows Remote Management service). This applies only to WMI namespaces that grant access to the 
                  user.
Name            : Remote Management Users
SID             : S-1-5-32-580
PrincipalSource : Local
ObjectClass     : Group
Description     : Supports file replication in a domain
Name            : Replicator
SID             : S-1-5-32-552
PrincipalSource : Local
ObjectClass     : Group
Description     : Members of this group are managed by the system.
Name            : System Managed Accounts Group
SID             : S-1-5-32-581
PrincipalSource : Local
ObjectClass     : Group
Description     : Members of this group may operate hardware from user mode.
Name            : User Mode Hardware Operators
SID             : S-1-5-32-584
PrincipalSource : Local
ObjectClass     : Group
Description     : Users are prevented from making accidental or intentional system-wide changes and can run most 
                  applications
Name            : Users
SID             : S-1-5-32-545
PrincipalSource : Local
ObjectClass     : Group
Aliases for \\WIN11
-------------------------------------------------------------------------------
*Administrators
*Access Control Assistance Operators
*Backup Operators
*Cryptographic Operators
*Device Owners
*Event Log Readers
*Guests
*Hyper-V Administrators
*IIS_IUSRS
*Network Configuration Operators
*OpenSSH Users
*Performance Log Users
*Performance Monitor Users
*Distributed COM Users
*Power Users
*Remote Desktop Users
*Remote Management Users
*Replicator
*System Managed Accounts Group
*User Mode Hardware Operators
*Users
The command completed successfully.
Exit code: 0
Done executing test:
T1087.001-9 Enumerate all accounts via PowerShell (Local)

Executing test:
T1087.001-10 Enumerate logged on users via CMD (Local)

USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
>alice.johnson         console             1  Active      none   7/14/2026 3:02 PM
Exit code: 1
Done executing test:
T1087.001-10 Enumerate logged on users via CMD (Local)

Executing test:
T1087.001-11 ESXi - Local Account Discovery via ESXCLI

The system cannot find the path specified.
Exit code: 255
Done executing test:
T1087.001-11 ESXi - Local Account Discovery via ESXCLI

