[Setup]
;INFO --> http://www.jrsoftware.org/ishelp/

; ****  Always generate a new GUID for every setup! ****
; (To generate a new GUID, click Tools > Generate GUID inside the IDE.)

AppId={{EA408AA2-29B2-46BB-B3E2-0EF7E379A25C}}
AppName=updater
AppVersion=2021.03.12.0
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
Name: "de"; MessagesFile: "compiler:Languages\German.isl"
Name: "nl"; MessagesFile: "compiler:Languages\Dutch.isl"
Name: "fi"; MessagesFile: "compiler:Languages\Finnish.isl"
Name: "fr"; MessagesFile: "compiler:Languages\French.isl"
Name: "he"; MessagesFile: "compiler:Languages\Hebrew.isl"
Name: "it"; MessagesFile: "compiler:Languages\Italian.isl"
Name: "jp"; MessagesFile: "compiler:Languages\Japanese.isl"
Name: "pt"; MessagesFile: "compiler:Languages\Portuguese.isl"
Name: "ru"; MessagesFile: "compiler:Languages\Russian.isl"
Name: "es"; MessagesFile: "compiler:Languages\Spanish.isl"
Name: "tr"; MessagesFile: "compiler:Languages\Turkish.isl"

; [Tasks]
; Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
;main executable
Source: "..\updater\bin\Release\updater.exe"; DestDir: "{app}"; Flags: ignoreversion
; NLog configuration file (logging)
Source: "..\updater\bin\Release\NLog.config"; DestDir: "{app}"; Flags: ignoreversion
; NLog main assembly (logging)
Source: "..\updater\packages\NLog.4.7.9\lib\net45\NLog.dll"; DestDir: "{app}"; Flags: ignoreversion
; GPL 3 license text
Source: "..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
; Start Menu entry for updater: check for new updates
Name: "{group}\Check for new updates"; Filename: "cmd.exe"; Parameters: "/k ""{app}\updater.exe"" check"
; Start Menu entry for updater: install updates
Name: "{group}\Download and install new updates (needs admin privileges)"; Filename: "cmd.exe"; Parameters: "/k ""{app}\updater.exe"" update"
; Start Menu entry for Uninstaller
Name: "{group}\Uninstall updater"; Filename: "{app}\unins000.exe"
;; Desktopicon (if selected during install - default is unselected)
;Name: "{commondesktop}\updater"; Filename: "{app}\updater.exe"; Parameters: "check"; Tasks: desktopicon
