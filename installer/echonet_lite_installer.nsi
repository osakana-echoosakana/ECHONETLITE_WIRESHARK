; ECHONET Lite Wireshark dissector - Windows installer (NSIS 3)
; Build:  makensis -DVERSION=1.0.0 installer/echonet_lite_installer.nsi
; Installs echonet_lite.lua into the current user's Wireshark personal
; Lua plugins folder (%APPDATA%\Wireshark\plugins). No admin rights needed.

Unicode true
!include "MUI2.nsh"
!include "FileFunc.nsh"

!ifndef VERSION
  !define VERSION "1.0.0"
!endif
!define APPNAME   "ECHONET Lite Wireshark Dissector"
!define APPKEY    "ECHONETLiteWiresharkDissector"
!define UNINSTKEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPKEY}"
!define PLUGINDIR "$APPDATA\Wireshark\plugins"
!define SRCDIR    ".."

Name "${APPNAME} ${VERSION}"
OutFile "${SRCDIR}\dist\echonet-lite-wireshark-setup-${VERSION}.exe"
InstallDir "$LOCALAPPDATA\${APPKEY}"
RequestExecutionLevel user
SetCompressor /SOLID lzma
ShowInstDetails show

VIProductVersion "${VERSION}.0"
VIAddVersionKey /LANG=0 "ProductName" "${APPNAME}"
VIAddVersionKey /LANG=0 "FileDescription" "${APPNAME} installer"
VIAddVersionKey /LANG=0 "FileVersion" "${VERSION}"
VIAddVersionKey /LANG=0 "ProductVersion" "${VERSION}"
VIAddVersionKey /LANG=0 "LegalCopyright" "MIT License"

!define MUI_ABORTWARNING
!define MUI_FINISHPAGE_TEXT "$(FinishText)"
!define MUI_FINISHPAGE_SHOWREADME "$INSTDIR\README.md"
!define MUI_FINISHPAGE_SHOWREADME_TEXT "$(ShowReadme)"
!define MUI_FINISHPAGE_SHOWREADME_NOTCHECKED

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "${SRCDIR}\LICENSE"
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "Japanese"
!insertmacro MUI_LANGUAGE "English"

LangString FinishText ${LANG_JAPANESE} "echonet_lite.lua を次のフォルダにインストールしました。$\r$\n$\r$\n${PLUGINDIR}$\r$\n$\r$\nWireshark を起動中の場合は再起動するか、[解析] → [Lua プラグインを再読み込み] (Ctrl+Shift+L) を実行してください。"
LangString FinishText ${LANG_ENGLISH} "echonet_lite.lua has been installed to:$\r$\n$\r$\n${PLUGINDIR}$\r$\n$\r$\nIf Wireshark is running, restart it or use Analyze > Reload Lua Plugins (Ctrl+Shift+L)."
LangString ShowReadme ${LANG_JAPANESE} "README を開く"
LangString ShowReadme ${LANG_ENGLISH} "Open README"
LangString RemovedMsg ${LANG_JAPANESE} "プラグインを削除しました。Wireshark を再起動してください。"
LangString RemovedMsg ${LANG_ENGLISH} "The plugin was removed. Please restart Wireshark."

Function .onInit
  !insertmacro MUI_LANGDLL_DISPLAY
FunctionEnd

Section "Install"
  ; Plugin
  SetOutPath "${PLUGINDIR}"
  File "${SRCDIR}\echonet_lite.lua"

  ; Docs, sample and uninstaller
  SetOutPath "$INSTDIR"
  File "${SRCDIR}\README.md"
  File "${SRCDIR}\LICENSE"
  File "${SRCDIR}\samples\echonet_lite_sample.pcap"
  WriteUninstaller "$INSTDIR\uninstall.exe"

  ; Add/Remove Programs entry (per user)
  WriteRegStr HKCU "${UNINSTKEY}" "DisplayName" "${APPNAME}"
  WriteRegStr HKCU "${UNINSTKEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKCU "${UNINSTKEY}" "Publisher" "ECHONETLITE_WIRESHARK"
  WriteRegStr HKCU "${UNINSTKEY}" "URLInfoAbout" "https://github.com/osakana-echoosakana/ECHONETLITE_WIRESHARK"
  WriteRegStr HKCU "${UNINSTKEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKCU "${UNINSTKEY}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKCU "${UNINSTKEY}" "QuietUninstallString" '"$INSTDIR\uninstall.exe" /S'
  WriteRegDWORD HKCU "${UNINSTKEY}" "NoModify" 1
  WriteRegDWORD HKCU "${UNINSTKEY}" "NoRepair" 1
  ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
  IntFmt $0 "0x%08X" $0
  WriteRegDWORD HKCU "${UNINSTKEY}" "EstimatedSize" "$0"
SectionEnd

Function un.onInit
  !insertmacro MUI_UNGETLANGUAGE
FunctionEnd

Section "Uninstall"
  Delete "${PLUGINDIR}\echonet_lite.lua"
  Delete "$INSTDIR\README.md"
  Delete "$INSTDIR\LICENSE"
  Delete "$INSTDIR\echonet_lite_sample.pcap"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"
  DeleteRegKey HKCU "${UNINSTKEY}"
  IfSilent +2
    MessageBox MB_OK|MB_ICONINFORMATION "$(RemovedMsg)"
SectionEnd
