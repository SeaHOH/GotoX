'启动 GotoX 系统托盘辅助工具。

Set fso = CreateObject("Scripting.FileSystemObject")
Set objShell = CreateObject("WScript.Shell")

objShell.CurrentDirectory = objShell.CurrentDirectory + "\python"

If fso.fileExists("install_dll.bat") Then
    Set objWMIService = GetObject("winmgmts:\\.\root\cimv2")
    Set colOperatingSystems = objWMIService.ExecQuery("Select * from Win32_OperatingSystem")
    For Each objOperatingSystem in colOperatingSystems
        if StrComp(objOperatingSystem.Version, "6.2") = -1 Then
            if MsgBox("在 Windows 7 下首次运行需安装 dll 文件。" & vbLf & vbLf & _
                      "已检测到安装脚本，是否运行？", _
                      vbYesNo + vbExclamation, "请确认") = vbYes then
                objShell.Run "install_dll.bat",,True
            End if
        End If
    Next
End If

objShell.Run "python.exe -E -s ..\launcher\start.py",,False
