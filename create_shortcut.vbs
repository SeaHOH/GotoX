'在桌面上生成 GotoX 的快捷方式。

Set fso = WScript.CreateObject("Scripting.FileSystemObject")
Set objShell = WScript.CreateObject("WScript.Shell")

linkFile = objShell.SpecialFolders("Desktop") & "\GotoX.lnk"
isCreateShortcut = True

if fso.fileExists(linkFile) then
    if MsgBox("快捷方式已经存在，是否覆盖？", _
              vbYesNo + vbExclamation, "请确认") = vbNo then
        isCreateShortcut = False
    End if
End if

if isCreateShortcut then
    Set link = objShell.CreateShortcut(linkFile)
    jsDirectory = fso.GetFile(WScript.ScriptFullName).ParentFolder.Path
    link.TargetPath = jsDirectory & "\python\python.exe"
    link.Arguments = "-E -s ..\launcher\start.py"
    link.WindowStyle = 7
    link.IconLocation = jsDirectory & "\GotoX.ico"
    link.Description = "GotoX"
    link.WorkingDirectory = jsDirectory & "\python"
    link.Save()
End if
