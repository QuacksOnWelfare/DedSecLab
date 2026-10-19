; DedSecLab - Inno Setup 6 installer
; Layout:
;   DedSecLab\
;     DedSecLabAPP_Beta\     <- app source; Nuitka output folder DedSecLab\ lives here after build.py
;     installer\             <- this folder
; Build:  powershell -ExecutionPolicy Bypass -File .\build_installer.ps1
; Requires: Inno Setup 6 (ISCC.exe), and ..\DedSecLabAPP_Beta\DedSecLab\DedSecLab.exe from build.py
; No code signing here - add your own SignTool steps if you need them.
; Inno skips Hidden/System files: build_installer.ps1 un-hides dist assets before compile;
; [Code] HideAssets re-hides them after install. Do not ship real dsl_upd.bin secrets in git.
#ifndef AppVersion
  #include "version.inc"
#endif

#define MyAppName       "DedSecLab"
#define MyAppPublisher  "DedSec Lab"
#define MyAppExeName    "DedSecLab.exe"
#define MyAppMutex      "DedSecLab_SingleInstance"
; Generate your OWN GUID for a public fork (Tools > Generate GUID in Inno).
; Keeping this GUID shares the same uninstall AppId as another build - change it if you redistribute.
#define MyAppId         "{{F8C36D03-DB70-493E-9BD5-0BD0E77C16B5}"
#define MyAppUninstId   "{F8C36D03-DB70-493E-9BD5-0BD0E77C16B5}_is1"

[Setup]
AppId={#MyAppId}
AppName={#MyAppName}
AppVersion={#AppVersion}
AppVerName={#MyAppName} {#AppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={localappdata}\Programs\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
; Terms of use + MIT licence on one must-accept page.
LicenseFile=LICENSE_AND_TERMS.txt
InfoBeforeFile=InfoBefore.txt
OutputDir=Output
OutputBaseFilename=DedSecLab-Setup-{#AppVersion}
SetupIconFile=assets\dedsec_logo.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
UninstallDisplayName={#MyAppName}
WizardStyle=modern
WizardSizePercent=120
WizardImageFile=assets\wizard_image.png,assets\wizard_image@2x.png
WizardSmallImageFile=assets\wizard_small.png,assets\wizard_small@2x.png
Compression=lzma2/max
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
; Per-user only under %LOCALAPPDATA% - NO PrivilegesRequiredOverridesAllowed,
; so the "Select install mode" dialog never appears. Keeps the self-updater
; able to replace files without elevation.
PrivilegesRequired=lowest
UsePreviousAppDir=yes
UsePreviousTasks=yes
UsePreviousGroup=yes
AllowNoIcons=yes
CloseApplications=yes
CloseApplicationsFilter=DedSecLab.exe,DedSecLabUpdater.exe
RestartApplications=no
AppMutex={#MyAppMutex}
VersionInfoVersion={#AppVersion}.0
VersionInfoCompany={#MyAppPublisher}
VersionInfoDescription={#MyAppName} Setup
VersionInfoProductName={#MyAppName}
VersionInfoProductVersion={#AppVersion}
VersionInfoCopyright=Copyright (C) 2026 {#MyAppPublisher}
SetupLogging=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Messages]
SetupAppTitle=DedSecLab Setup
SetupWindowTitle=DedSecLab Setup - %1
WelcomeLabel1=Welcome to DedSecLab Setup
WelcomeLabel2=This will install [name/ver] on your computer.%n%nIt is recommended that you close DedSecLab and other applications before continuing.%n%nClick Next to continue, or Cancel to exit Setup.
FinishedHeadingLabel=Completing DedSecLab Setup
FinishedLabelNoIcons=Setup has finished installing DedSecLab on your computer.
FinishedLabel=Setup has finished installing DedSecLab on your computer. The application may be launched by selecting the installed shortcuts.
ClickFinish=Click Finish to exit Setup.
WizardLicense=Terms of use and licence
LicenseLabel=Please read the terms of use and licence before continuing.
LicenseLabel3=Please read the following terms of use and licence. You must accept them before continuing with the installation.
LicenseAccepted=I &accept the terms of use and licence
LicenseNotAccepted=I &do not accept
InfoBeforeLabel=Please read the following information before continuing.
InfoBeforeClickLabel=When you are ready to continue with Setup, click Next.
ConfirmUninstall=Are you sure you want to completely remove %1 and all of its components?
UninstalledAll=%1 was successfully removed from your computer.

[CustomMessages]
CreateDesktopIcon=Create a &desktop shortcut
LaunchApp=Launch DedSecLab
RemoveUserData=Also remove my DedSecLab settings and local data?
RemoveUserDataNote=This deletes saved settings and local cache under AppData.%nSign-in credentials stored by Windows Credential Manager are left alone.
NewerAlreadyInstalled=A newer version of DedSecLab (%1) is already installed. Setup will now exit.

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: checkedonce

[Files]
; Entire Nuitka standalone dist (exe, DLLs, assets incl. hidden assets\dsl_upd.bin).
; Source assets must be un-hidden before compile (see build_installer.ps1).
Source: "..\DedSecLabAPP_Beta\DedSecLab\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; IconFilename: "{app}\assets\dedsec_logo.ico"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; IconFilename: "{app}\assets\dedsec_logo.ico"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchApp}"; Flags: nowait postinstall skipifsilent; WorkingDir: "{app}"

[UninstallDelete]
; Leftover files created at runtime next to the exe (never touch AppData here).
Type: files; Name: "{app}\*.log"
Type: filesandordirs; Name: "{app}\.dedsec-update-backup"

[Code]
const
  UninstKey = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\{#MyAppUninstId}';
  AppDataDirName = 'DedSecLab';

function SetFileAttributesW(lpFileName: String; dwFileAttributes: DWORD): Boolean;
  external 'SetFileAttributesW@kernel32.dll stdcall';

function GetInstalledVersion(var Version: String): Boolean;
begin
  Result := RegQueryStringValue(HKCU, UninstKey, 'DisplayVersion', Version);
  if not Result then
    Result := RegQueryStringValue(HKLM, UninstKey, 'DisplayVersion', Version);
end;

function CompareVersionParts(const A, B: String): Integer;
var
  VA, VB: Int64;
begin
  if not StrToVersion(A, VA) then
  begin
    Result := 0;
    Exit;
  end;
  if not StrToVersion(B, VB) then
  begin
    Result := 0;
    Exit;
  end;
  Result := ComparePackedVersion(VA, VB);
end;

function InitializeSetup(): Boolean;
var
  Installed: String;
begin
  Result := True;
  if GetInstalledVersion(Installed) then
  begin
    if CompareVersionParts(Installed, '{#AppVersion}') > 0 then
    begin
      MsgBox(FmtMessage(CustomMessage('NewerAlreadyInstalled'), [Installed]),
        mbInformation, MB_OK);
      Result := False;
    end;
  end;
end;

{ Re-apply Hidden+System to assets after install so users cannot casually see/edit them.
  FILE_ATTRIBUTE_HIDDEN and FILE_ATTRIBUTE_SYSTEM are predefined by Inno - do not redeclare. }
procedure HideAssets;
begin
  SetFileAttributesW(ExpandConstant('{app}\assets'), FILE_ATTRIBUTE_HIDDEN or FILE_ATTRIBUTE_SYSTEM);
  if FileExists(ExpandConstant('{app}\assets\dsl_upd.bin')) then
    SetFileAttributesW(ExpandConstant('{app}\assets\dsl_upd.bin'), FILE_ATTRIBUTE_HIDDEN or FILE_ATTRIBUTE_SYSTEM);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
    HideAssets;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  AppDataPath: String;
begin
  if CurUninstallStep <> usPostUninstall then
    Exit;

  AppDataPath := ExpandConstant('{userappdata}\' + AppDataDirName);
  if not DirExists(AppDataPath) then
    Exit;

  if MsgBox(
       CustomMessage('RemoveUserData') + #13#10#13#10 + CustomMessage('RemoveUserDataNote'),
       mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
  begin
    DelTree(AppDataPath, True, True, True);
  end;
end;
