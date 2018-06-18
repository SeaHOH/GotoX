'启动 GotoX 系统托盘辅助工具，位于 GotoX 根目录下有效。
'也可以用 create_shortcut.js 在桌面创建 GotoX 的快捷方式。
Dim objShell
Set objShell = WScript.CreateObject("WScript.Shell")
objShell.CurrentDirectory = objShell.CurrentDirectory + "\python"
objShell.Run "python.exe ..\launcher\win32.py",,False
Set objShell = NoThing
WScript.quit
