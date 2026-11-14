; Game Kernel — Windows installer (Inno Setup 6).
;
; Installs the folder assembled by tools/make_distribution.py (it already contains the integrity manifest):
;   iscc /DAppVersion=1.0.0 /DSourceDir=<repo>\dist\GameKernel /DOutputDir=<repo>\dist installer\gamekernel.iss
;
; Offline by design: the installer downloads nothing, opens no web page and registers no update task.
; User data (%LOCALAPPDATA%\GameKernel: database, quarantine, reports, settings, installed signature updates)
; is never removed by the uninstaller — the quarantine holds the user's own files.

#ifndef AppVersion
  #error Defina /DAppVersion=x.y.z (python tools/make_distribution.py --print-version)
#endif
#ifndef SourceDir
  #error Defina /DSourceDir=<pasta montada por tools/make_distribution.py>
#endif
#ifndef OutputDir
  #define OutputDir "..\dist"
#endif

#define AppName "Game Kernel"
#define AppExe "GameKernel.exe"

[Setup]
; Stable identifier of the product: upgrades replace the same installation.
AppId={{6F0C2B7E-4A1D-4E8B-9C3A-2D5B7E1F9A40}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppName}
VersionInfoVersion={#AppVersion}.0
VersionInfoProductName={#AppName}
VersionInfoDescription=Instalador do {#AppName} — antivírus offline para jogos
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
; Program Files by default; a per-user installation can be chosen in the first page or with /CURRENTUSER.
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=dialog commandline
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.17763
OutputDir={#OutputDir}
OutputBaseFilename=GameKernel-{#AppVersion}-setup
SetupIconFile=..\assets\gamekernel.ico
UninstallDisplayIcon={app}\{#AppExe}
UninstallDisplayName={#AppName}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes
RestartApplications=no

[Languages]
Name: "brazilianportuguese"; MessagesFile: "compiler:Languages\BrazilianPortuguese.isl"

[Tasks]
Name: "desktopicon"; Description: "Criar atalho na Área de Trabalho"; GroupDescription: "Atalhos:"; Flags: unchecked

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExe}"
Name: "{group}\Desinstalar o {#AppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExe}"; Description: "Abrir o {#AppName}"; Flags: nowait postinstall skipifsilent

[Code]
function DataDir(): String;
begin
  Result := ExpandConstant('{localappdata}\GameKernel');
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if (CurUninstallStep = usPostUninstall) and DirExists(DataDir()) and not UninstallSilent() then
    MsgBox('O programa foi removido. Os seus dados foram mantidos em:' + #13#10 + DataDir() + #13#10#13#10 +
           'Essa pasta guarda o histórico, os relatórios, as configurações e a QUARENTENA (arquivos seus, ' +
           'criptografados). Restaure o que precisar antes de apagá-la manualmente.', mbInformation, MB_OK);
end;
