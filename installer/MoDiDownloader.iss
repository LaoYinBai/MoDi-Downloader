#ifndef AppVersion
  #define AppVersion "1.0.0"
#endif
#ifndef SharedAudienceVerified
  #error Use tools/BuildMoDiDownloaderSetup.ps1 to validate the shared payload first.
#endif
#ifndef PublishDir
  #define PublishDir "..\artifacts\publish\win-x64"
#endif

[Setup]
AppId={{29B6A0C0-FAC3-4570-9645-C0F41E65A1C7}
AppName=MoDi Downloader
AppVersion={#AppVersion}
AppPublisher=MoDi
AppPublisherURL=https://github.com/LaoYinBai/MoDi-Downloader
DefaultDirName={localappdata}\Programs\MoDiDownloader
DefaultGroupName=MoDi Downloader
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\artifacts\release
OutputBaseFilename=MoDiDownloader-{#AppVersion}-win-x64-setup
SetupIconFile=..\src\SshSpeedDownloader.Desktop\Assets\modi-downloader.ico
UninstallDisplayIcon={app}\MoDiDownloader.exe
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes
RestartApplications=no
DisableProgramGroupPage=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "chinesesimplified"; MessagesFile: "compiler:Languages\ChineseSimplified.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Shortcuts:"; Flags: checkedonce

[Files]
Source: "{#PublishDir}\MoDiDownloader.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\MoDi Downloader"; Filename: "{app}\MoDiDownloader.exe"
Name: "{autodesktop}\MoDi Downloader"; Filename: "{app}\MoDiDownloader.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\MoDiDownloader.exe"; Description: "Launch MoDi Downloader"; Flags: nowait postinstall skipifsilent
