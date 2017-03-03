'启动 GotoX 系统托盘辅助工具，位于 GotoX 根目录下有效。
'也可以创建 GotoX\python\python.exe 的快捷方式来启动，
'需要在属性->快捷方式->目标栏末尾添加“ ..\launcher\win32.py”。
Dim objShell
Set objShell = WScript.CreateObject("WScript.Shell")
objShell.CurrentDirectory = objShell.CurrentDirectory + "\python"
objShell.Run "python.exe ..\launcher\win32.py",,False
Set objShell = NoThing
WScript.quit
