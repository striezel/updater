[Setup]
;INFO --> http://www.jrsoftware.org/ishelp/

; ****  Always generate a new GUID for every setup! ****
; (To generate a new GUID, click Tools > Generate GUID inside the IDE.)

AppId={{EA408AA2-29B2-46BB-B3E2-0EF7E379A25C}}
AppName=updater
AppVersion=2023.07.13.0
AppPublisher=Dirk Stolle
AppPublisherURL=https://github.com/striezel/updater
AppSupportURL=https://github.com/striezel/updater
AppUpdatesURL=https://github.com/striezel/updater
DefaultDirName={pf}\updater
DisableDirPage=no
DefaultGroupName=updater
DisableProgramGroupPage=no
OutputDir=..\output
OutputBaseFilename=updater_setup
Compression=lzma
SolidCompression=yes
; icon for installer
; SetupIconFile=todo.ico

[Languages]
Name: "en"; MessagesFile: "compiler:Default.isl"
Name: "ca"; MessagesFile: "compiler:Languages\Catalan.isl"
Name: "co"; MessagesFile: "compiler:Languages\Corsican.isl"
Name: "cs"; MessagesFile: "compiler:Languages\Czech.isl"
Name: "da"; MessagesFile: "compiler:Languages\Danish.isl"
Name: "nl"; MessagesFile: "compiler:Languages\Dutch.isl"
Name: "fi"; MessagesFile: "compiler:Languages\Finnish.isl"
Name: "fr"; MessagesFile: "compiler:Languages\French.isl"
Name: "de"; MessagesFile: "compiler:Languages\German.isl"
Name: "he"; MessagesFile: "compiler:Languages\Hebrew.isl"
Name: "it"; MessagesFile: "compiler:Languages\Italian.isl"
Name: "jp"; MessagesFile: "compiler:Languages\Japanese.isl"
Name: "no"; MessagesFile: "compiler:Languages\Norwegian.isl"
Name: "pl"; MessagesFile: "compiler:Languages\Polish.isl"
Name: "pt"; MessagesFile: "compiler:Languages\Portuguese.isl"
Name: "ru"; MessagesFile: "compiler:Languages\Russian.isl"
Name: "sl"; MessagesFile: "compiler:Languages\Slovenian.isl"
Name: "es"; MessagesFile: "compiler:Languages\Spanish.isl"
Name: "tr"; MessagesFile: "compiler:Languages\Turkish.isl"
Name: "uk"; MessagesFile: "compiler:Languages\Ukrainian.isl"

; [Tasks]
; Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
;main executable
Source: "..\updater\bin\Release\net6.0-windows\updater.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\updater\bin\Release\net6.0-windows\updater.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\updater\bin\Release\net6.0-windows\updater.runtimeconfig.json"; DestDir: "{app}"; Flags: ignoreversion
; Newtonsoft.Json assembly (JSON deserialization)
Source: "{#GetEnv('USERPROFILE')}\.nuget\packages\newtonsoft.json\13.0.3\lib\netstandard2.0\Newtonsoft.Json.dll"; DestDir: "{app}"; Flags: ignoreversion
; NLog main assembly (logging)
Source: "{#GetEnv('USERPROFILE')}\.nuget\packages\nlog\5.2.2\lib\netstandard2.0\NLog.dll"; DestDir: "{app}"; Flags: ignoreversion
; GPL 3 license text
Source: "..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
; documentation files
Source: "..\readme.md"; DestDir: "{app}\documentation"; Flags: ignoreversion
Source: "..\changelog.md"; DestDir: "{app}\documentation"; Flags: ignoreversion
Source: "..\faq.md"; DestDir: "{app}\documentation"; Flags: ignoreversion
Source: "..\supported_applications.md"; DestDir: "{app}\documentation"; Flags: ignoreversion

[Icons]
; Start Menu entry for updater: check for new updates
Name: "{group}\Check for new updates"; Filename: "cmd.exe"; Parameters: "/k ""{app}\updater.exe"" check"
; Start Menu entry for updater: install updates
Name: "{group}\Download and install new updates (needs admin privileges)"; Filename: "cmd.exe"; Parameters: "/k ""{app}\updater.exe"" update"
; Start Menu entry for Uninstaller
Name: "{group}\Uninstall updater"; Filename: "{app}\unins000.exe"
;; Desktopicon (if selected during install - default is unselected)
;Name: "{commondesktop}\updater"; Filename: "{app}\updater.exe"; Parameters: "check"; Tasks: desktopicon
