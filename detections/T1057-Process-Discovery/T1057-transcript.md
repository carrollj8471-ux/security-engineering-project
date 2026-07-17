**********************
Windows PowerShell transcript start
Start time: 20260715142343
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
Transcript started, output file is C:\Temp\T1057-transcript.txt
PS C:\WINDOWS\system32> Get-Date

Wednesday, July 15, 2026 2:23:43 PM


PS C:\WINDOWS\system32> hostname
WIN11
PS C:\WINDOWS\system32> whoami
corp\administrator
PS C:\WINDOWS\system32> Invoke-AtomicTest T1057 `
  -PathToAtomicsFolder "C:\AtomicRedTeam\atomics" `
  -TestNumbers 9
PathToAtomicsFolder = C:\AtomicRedTeam\atomics
Executing test:
T1057-9 Launch Taskmgr from cmd to View running processes

Exit code: 0
Done executing test:
T1057-9 Launch Taskmgr from cmd to View running processes

PS C:\WINDOWS\system32> Invoke-AtomicTest T1057 `
  -PathToAtomicsFolder "C:\AtomicRedTeam\atomics" `
  -TestNumbers 2
PathToAtomicsFolder = C:\AtomicRedTeam\atomics
Executing test:
T1057-2 Process Discovery - tasklist

Image Name                     PID Session Name        Session#    Mem Usage
========================= ======== ================ =========== ============
System Idle Process              0 Services                   0          8 K
System                           4 Services                   0        168 K
Registry                        96 Services                   0     53,280 K
smss.exe                       420 Services                   0      1,476 K
csrss.exe                      600 Services                   0      7,088 K
csrss.exe                      680 Console                    1     21,284 K
wininit.exe                    688 Services                   0      9,872 K
winlogon.exe                   752 Console                    1     16,932 K
services.exe                   824 Services                   0     16,008 K
lsass.exe                      844 Services                   0     34,868 K
svchost.exe                    976 Services                   0     41,168 K
fontdrvhost.exe               1004 Services                   0      4,368 K
fontdrvhost.exe               1000 Console                    1      6,672 K
svchost.exe                    576 Services                   0     19,404 K
svchost.exe                    876 Services                   0     10,824 K
dwm.exe                       1072 Console                    1     96,440 K
svchost.exe                   1192 Services                   0      8,136 K
svchost.exe                   1228 Services                   0      8,372 K
svchost.exe                   1240 Services                   0     10,860 K
svchost.exe                   1348 Services                   0     10,512 K
svchost.exe                   1384 Services                   0     15,860 K
svchost.exe                   1392 Services                   0     13,208 K
svchost.exe                   1432 Services                   0     14,096 K
svchost.exe                   1512 Services                   0     13,828 K
svchost.exe                   1524 Services                   0      8,792 K
svchost.exe                   1600 Services                   0     20,028 K
svchost.exe                   1616 Services                   0     21,408 K
svchost.exe                   1676 Services                   0     13,548 K
svchost.exe                   1768 Services                   0     11,456 K
svchost.exe                   1936 Services                   0     10,308 K
svchost.exe                   2036 Services                   0     51,496 K
svchost.exe                    728 Services                   0     11,120 K
svchost.exe                   1988 Services                   0     19,044 K
svchost.exe                   2052 Services                   0      7,588 K
svchost.exe                   2184 Services                   0     14,996 K
svchost.exe                   2208 Services                   0     11,884 K
Memory Compression            2220 Services                   0    283,316 K
svchost.exe                   2264 Services                   0     17,148 K
svchost.exe                   2324 Services                   0     11,364 K
svchost.exe                   2344 Services                   0     10,144 K
svchost.exe                   2488 Services                   0     18,536 K
svchost.exe                   2608 Services                   0     12,420 K
svchost.exe                   2616 Services                   0     12,744 K
svchost.exe                   2728 Services                   0     26,884 K
svchost.exe                   2736 Services                   0     18,616 K
spoolsv.exe                   2888 Services                   0     18,628 K
svchost.exe                   2936 Services                   0     10,792 K
svchost.exe                   3044 Services                   0     22,048 K
svchost.exe                   3052 Services                   0     60,848 K
svchost.exe                   3064 Services                   0     38,584 K
svchost.exe                   1696 Services                   0     10,148 K
MpDefenderCoreService.exe     2572 Services                   0     24,720 K
svchost.exe                   2744 Services                   0     12,328 K
VGAuthService.exe             3104 Services                   0     12,764 K
svchost.exe                   3088 Services                   0      6,972 K
vmtoolsd.exe                  3116 Services                   0     24,204 K
vm3dservice.exe               3136 Services                   0      8,912 K
wazuh-agent.exe               3152 Services                   0     37,340 K
svchost.exe                   3168 Services                   0     23,936 K
MsMpEng.exe                   3192 Services                   0    180,156 K
svchost.exe                   3200 Services                   0     26,120 K
Sysmon.exe                    3428 Services                   0     22,984 K
vm3dservice.exe               3448 Console                    1     10,340 K
dllhost.exe                   3808 Services                   0     16,248 K
unsecapp.exe                  3852 Services                   0      9,276 K
WmiPrvSE.exe                  3904 Services                   0     29,924 K
msdtc.exe                     4156 Services                   0     11,836 K
svchost.exe                   5072 Services                   0     18,804 K
svchost.exe                   3868 Services                   0      9,568 K
AggregatorHost.exe            4312 Services                   0     11,896 K
svchost.exe                   4728 Services                   0      9,752 K
svchost.exe                   5128 Services                   0     10,784 K
svchost.exe                   5336 Services                   0     23,428 K
svchost.exe                   5460 Services                   0     27,532 K
svchost.exe                   5628 Services                   0     29,408 K
NisSrv.exe                    5836 Services                   0     13,660 K
svchost.exe                   4072 Services                   0     10,080 K
svchost.exe                   6072 Services                   0     14,728 K
svchost.exe                   5848 Services                   0     23,636 K
svchost.exe                    712 Services                   0      9,876 K
svchost.exe                   1412 Services                   0     33,140 K
svchost.exe                   2252 Services                   0     15,576 K
svchost.exe                   3228 Services                   0     33,068 K
svchost.exe                   4468 Services                   0     13,012 K
SearchIndexer.exe             5420 Services                   0     40,620 K
svchost.exe                   1912 Services                   0     13,784 K
sihost.exe                    2664 Console                    1     52,276 K
svchost.exe                   3388 Console                    1     24,588 K
svchost.exe                   2784 Console                    1     10,112 K
svchost.exe                   3132 Console                    1     39,552 K
taskhostw.exe                 6104 Console                    1     22,600 K
MicrosoftEdgeUpdate.exe       3888 Services                   0      8,452 K
explorer.exe                  2516 Console                    1    296,116 K
ShellHost.exe                 2312 Console                    1     40,692 K
svchost.exe                   6476 Services                   0     15,280 K
CrossDeviceResume.exe         6700 Console                    1     52,060 K
svchost.exe                   7796 Console                    1     22,432 K
dllhost.exe                   8064 Console                    1     12,132 K
svchost.exe                   7616 Console                    1     29,236 K
SearchHost.exe                8164 Console                    1    124,988 K
StartMenuExperienceHost.e     5648 Console                    1    155,428 K
RuntimeBroker.exe             7992 Console                    1     61,372 K
svchost.exe                   7944 Console                    1     24,660 K
msedgewebview2.exe            8576 Console                    1    124,800 K
msedgewebview2.exe            8648 Console                    1     14,920 K
msedgewebview2.exe            6836 Console                    1     47,008 K
msedgewebview2.exe            6760 Console                    1     44,404 K
msedgewebview2.exe            8444 Console                    1     23,456 K
msedgewebview2.exe            9044 Console                    1    103,396 K
Widgets.exe                   9544 Console                    1     72,408 K
WidgetService.exe             9604 Console                    1     27,164 K
ctfmon.exe                    9788 Console                    1     33,824 K
TabTip.exe                    9800 Console                    1     53,076 K
svchost.exe                   9972 Services                   0     26,252 K
UserOOBEBroker.exe            9660 Console                    1     10,652 K
RuntimeBroker.exe             6496 Console                    1     36,852 K
SecurityHealthSystray.exe     5548 Console                    1     13,296 K
SecurityHealthService.exe     2388 Services                   0     25,964 K
vmtoolsd.exe                  6132 Console                    1     23,384 K
OneDrive.exe                 10268 Console                    1     81,588 K
TextInputHost.exe            10848 Console                    1     74,560 K
backgroundTaskHost.exe       11248 Console                    1     68,264 K
dllhost.exe                  10484 Console                    1     21,984 K
msedgewebview2.exe            9444 Console                    1      9,120 K
msedgewebview2.exe           10584 Console                    1     15,560 K
msedgewebview2.exe           10548 Console                    1      4,612 K
msedgewebview2.exe            7900 Console                    1      2,208 K
msedgewebview2.exe            1960 Console                    1         16 K
msedgewebview2.exe           11068 Console                    1      5,396 K
ShellExperienceHost.exe       5256 Console                    1     66,128 K
RuntimeBroker.exe             8276 Console                    1     22,152 K
RuntimeBroker.exe             9372 Console                    1     18,204 K
cmd.exe                       1020 Console                    1      5,748 K
conhost.exe                  10840 Console                    1     20,660 K
LockApp.exe                   3700 Console                    1     95,172 K
RuntimeBroker.exe             8900 Console                    1     55,244 K
svchost.exe                   8304 Console                    1     16,540 K
svchost.exe                   6100 Services                   0     36,812 K
svchost.exe                  10524 Services                   0     11,968 K
svchost.exe                  10244 Console                    1     29,408 K
mmc.exe                       7268 Console                    1     64,856 K
dllhost.exe                   5916 Console                    1     14,688 K
powershell.exe                2640 Console                    1    144,020 K
conhost.exe                   5192 Console                    1     22,228 K
svchost.exe                   5092 Services                   0     12,540 K
MoNotificationUx.exe          7876 Console                    1     13,440 K
OneDrive.Sync.Service.exe     5288 Console                    1      8,704 K
svchost.exe                  10824 Services                   0      8,644 K
svchost.exe                   4028 Services                   0      7,372 K
msedge.exe                    7428 Console                    1    137,776 K
msedge.exe                    3880 Console                    1     12,444 K
msedge.exe                   11324 Console                    1     29,032 K
msedge.exe                   11460 Console                    1     41,996 K
msedge.exe                   11636 Console                    1     19,364 K
msedge.exe                   11308 Console                    1     97,696 K
msedge.exe                    8056 Console                    1     30,436 K
msedge.exe                    5292 Console                    1     19,548 K
svchost.exe                   1252 Services                   0     16,672 K
SearchProtocolHost.exe        5996 Services                   0     21,008 K
SearchFilterHost.exe          2380 Services                   0     12,984 K
cmd.exe                       8464 Console                    1      7,228 K
conhost.exe                   9496 Console                    1      7,828 K
tasklist.exe                 11060 Console                    1     11,852 K
Exit code: 0
Done executing test:
T1057-2 Process Discovery - tasklist

