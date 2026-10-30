[Setup]
AppId={{8F94A2D1-1410-4B7E-9A2C-JYOTIPRIYO141}
AppName=GhostBlade-141 (Signature Edition)
AppVersion=1.0.0
AppPublisher=Jyotipriyo Saha
AppCopyright=Copyright (C) 2026 Jyotipriyo Saha
DefaultDirName={autopf}\GhostBlade-141
DefaultGroupName=GhostBlade-141
LicenseFile=LICENSE.txt
SetupIconFile=assets\ghostblade.ico
UninstallDisplayIcon={app}\GhostBlade141.exe
OutputDir=installer_output
OutputBaseFilename=GhostBlade141_Setup_v1.0.0
Compression=lzma2/fast
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayName=GhostBlade-141 (By Jyotipriyo Saha)

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
Source: "dist\GhostBlade141\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "LICENSE.txt"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\GhostBlade-141"; Filename: "{app}\GhostBlade141.exe"; IconFilename: "{app}\GhostBlade141.exe"
Name: "{group}\Uninstall GhostBlade-141"; Filename: "{uninstallexe}"
Name: "{autodesktop}\GhostBlade-141"; Filename: "{app}\GhostBlade141.exe"; IconFilename: "{app}\GhostBlade141.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\GhostBlade141.exe"; Description: "{cm:LaunchProgram,GhostBlade-141}"; Flags: nowait postinstall skipifsilent shellexec
