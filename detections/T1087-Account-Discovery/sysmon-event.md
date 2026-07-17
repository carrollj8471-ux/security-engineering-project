- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
- <System>
  <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}" /> 
  <EventID>1</EventID> 
  <Version>5</Version> 
  <Level>4</Level> 
  <Task>1</Task> 
  <Opcode>0</Opcode> 
  <Keywords>0x8000000000000000</Keywords> 
  <TimeCreated SystemTime="2026-07-16T17:19:01.6579506Z" /> 
  <EventRecordID>15964</EventRecordID> 
  <Correlation /> 
  <Execution ProcessID="3428" ThreadID="4532" /> 
  <Channel>Microsoft-Windows-Sysmon/Operational</Channel> 
  <Computer>WIN11.corp.local</Computer> 
  <Security UserID="S-1-5-18" /> 
  </System>
- <EventData>
  <Data Name="RuleName">-</Data> 
  <Data Name="UtcTime">2026-07-16 17:19:01.649</Data> 
  <Data Name="ProcessGuid">{4bc15048-1285-6a59-4c0a-000000000d00}</Data> 
  <Data Name="ProcessId">10280</Data> 
  <Data Name="Image">C:\Windows\System32\query.exe</Data> 
  <Data Name="FileVersion">10.0.26100.7623 (WinBuild.160101.0800)</Data> 
  <Data Name="Description">MultiUser Query Utility</Data> 
  <Data Name="Product">Microsoft® Windows® Operating System</Data> 
  <Data Name="Company">Microsoft Corporation</Data> 
  <Data Name="OriginalFileName">query.exe</Data> 
  <Data Name="CommandLine">query user</Data> 
  <Data Name="CurrentDirectory">C:\Users\ADMINI~1\AppData\Local\Temp\</Data> 
  <Data Name="User">CORP\Administrator</Data> 
  <Data Name="LogonGuid">{4bc15048-b7b3-6a56-6730-650200000000}</Data> 
  <Data Name="LogonId">0x2653067</Data> 
  <Data Name="TerminalSessionId">1</Data> 
  <Data Name="IntegrityLevel">High</Data> 
  <Data Name="Hashes">MD5=97790914262832C7C48516CD2BBF34F6,SHA256=2824145EFA3C6EFDCBD9989B912A0DB72C7AC305DC230583470558D20F97B0FF,IMPHASH=CCC9DA4A55E90DFE34CBCDB066D6A6B3</Data> 
  <Data Name="ParentProcessGuid">{4bc15048-1285-6a59-4a0a-000000000d00}</Data> 
  <Data Name="ParentProcessId">456</Data> 
  <Data Name="ParentImage">C:\Windows\System32\cmd.exe</Data> 
  <Data Name="ParentCommandLine">"cmd.exe" /c query user</Data> 
  <Data Name="ParentUser">CORP\Administrator</Data> 
  </EventData>
  </Event>