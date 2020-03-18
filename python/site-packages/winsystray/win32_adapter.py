import ctypes
import locale
import sys

RegisterWindowMessage = ctypes.windll.user32.RegisterWindowMessageA
LoadCursor = ctypes.windll.user32.LoadCursorA
LoadIcon = ctypes.windll.user32.LoadIconA
LoadImage = ctypes.windll.user32.LoadImageA
RegisterClass = ctypes.windll.user32.RegisterClassA
CreateWindowEx = ctypes.windll.user32.CreateWindowExA
UpdateWindow = ctypes.windll.user32.UpdateWindow
DefWindowProc = ctypes.windll.user32.DefWindowProcA
GetSystemMetrics = ctypes.windll.user32.GetSystemMetrics
InsertMenuItem = ctypes.windll.user32.InsertMenuItemA
PostMessage = ctypes.windll.user32.PostMessageA
PostQuitMessage = ctypes.windll.user32.PostQuitMessage
SetMenuDefaultItem = ctypes.windll.user32.SetMenuDefaultItem
GetCursorPos = ctypes.windll.user32.GetCursorPos
SetForegroundWindow = ctypes.windll.user32.SetForegroundWindow
TrackPopupMenu = ctypes.windll.user32.TrackPopupMenu
CreatePopupMenu = ctypes.windll.user32.CreatePopupMenu
CreateCompatibleDC = ctypes.windll.gdi32.CreateCompatibleDC
GetDC = ctypes.windll.user32.GetDC
CreateCompatibleBitmap = ctypes.windll.gdi32.CreateCompatibleBitmap
GetSysColorBrush = ctypes.windll.user32.GetSysColorBrush
FillRect = ctypes.windll.user32.FillRect
DrawIconEx = ctypes.windll.user32.DrawIconEx
SelectObject = ctypes.windll.gdi32.SelectObject
DeleteDC = ctypes.windll.gdi32.DeleteDC
DestroyWindow = ctypes.windll.user32.DestroyWindow
GetModuleHandle = ctypes.windll.kernel32.GetModuleHandleA
GetMessage = ctypes.windll.user32.GetMessageA
TranslateMessage = ctypes.windll.user32.TranslateMessage
DispatchMessage = ctypes.windll.user32.DispatchMessageA
Shell_NotifyIcon = ctypes.windll.shell32.Shell_NotifyIcon
DestroyIcon = ctypes.windll.user32.DestroyIcon

NIM_ADD = 0
NIM_MODIFY = 1
NIM_DELETE = 2
NIF_MESSAGE = 1
NIF_MESSAGE = 1
NIF_ICON = 2
NIF_TIP = 4
NIF_INFO = 16
NIIF_INFO = 1
NIIF_WARNING = 2
NIIF_ERROR = 3
NIIF_USER = 4
NIIF_NOSOUND = 16
NIIF_LARGE_ICON = 32
MIIM_STATE = 1
MIIM_ID = 2
MIIM_SUBMENU = 4
MIIM_STRING = 64
MIIM_BITMAP = 128
MIIM_FTYPE = 256
WM_DESTROY = 2
WM_CLOSE = 16
WM_COMMAND = 273
WM_USER = 1024
WM_LBUTTONDBLCLK = 515
WM_RBUTTONUP = 517
WM_LBUTTONUP = 514
WM_NULL = 0
CS_VREDRAW = 1
CS_HREDRAW = 2
IDC_ARROW = 32512
COLOR_WINDOW = 5
WS_OVERLAPPED = 0
WS_SYSMENU = 524288
CW_USEDEFAULT = -2147483648
LR_LOADFROMFILE = 16
LR_DEFAULTSIZE = 64
IMAGE_ICON = 1
IDI_APPLICATION = 32512
TPM_LEFTALIGN = 0
SM_CXSMICON = 49
SM_CYSMICON = 50
COLOR_MENU = 4
DI_NORMAL = 3
MFT_MENUBARBREAK = 32
MFT_MENUBREAK = 64
MFT_OWNERDRAW = 256
MFT_RADIOCHECK = 512
MFT_SEPARATOR = 2048
MFT_RIGHTORDER = 8192
MFT_RIGHTJUSTIFY = 16384
MFS_ENABLED = 0
MFS_DISABLED = 3
MFS_CHECKED = 8
MFS_HILITE = 128
MFS_DEFAULT = 4096

SZTIP_MAX_LENGTH = 128
SZINFO_MAX_LENGTH = 256
SZINFOTITLE_MAX_LENGTH = 64


from ctypes.wintypes import *

HCURSOR = HANDLE
LRESULT = LPARAM
ULONG_PTR = WPARAM
WNDPROC = ctypes.CFUNCTYPE(LRESULT, HWND, UINT, WPARAM, LPARAM)


LOCALE_ENCODING = locale.getpreferredencoding()

def encode_for_locale(s):
    """
    Encode text items for system locale. If encoding fails, fall back to ASCII.
    """
    try:
        return s.encode(LOCALE_ENCODING, 'ignore')
    except (AttributeError, UnicodeDecodeError):
        return s.decode('ascii', 'ignore').encode(LOCALE_ENCODING)

class WNDCLASS(ctypes.Structure):
    _fields_ = [("style", UINT),
                ("lpfnWndProc", WNDPROC),
                ("cbClsExtra", INT),
                ("cbWndExtra", INT),
                ("hInstance", HINSTANCE),
                ("hIcon", HICON),
                ("hCursor", HCURSOR),
                ("hbrBackground", HANDLE),
                ("lpszMenuName", LPCSTR),
                ("lpszClassName", LPCSTR),
               ]

class MENUITEMINFO(ctypes.Structure):
    _fields_ = [("cbSize", UINT),
                ("fMask", UINT),
                ("fType", UINT),
                ("fState", UINT),
                ("wID", UINT),
                ("hSubMenu", HMENU),
                ("hbmpChecked", HBITMAP),
                ("hbmpUnchecked", HBITMAP),
                ("dwItemData", ULONG_PTR),
                ("dwTypeData", LPSTR),
                ("cch", UINT),
                ("hbmpItem", HBITMAP),
               ]

class GUID(ctypes.Structure):
    _fields_ = [("Data1", ULONG),
                ("Data2", USHORT),
                ("Data3", USHORT),
                ("Data4", CHAR * 8),
               ]

class NOTIFYICONDATA(ctypes.Structure):
    _fields_ = [("cbSize", DWORD),
                ("hWnd", HWND),
                ("uID", UINT),
                ("uFlags", UINT),
                ("uCallbackMessage", UINT),
                ("hIcon", HICON),
                ("szTip", CHAR * SZTIP_MAX_LENGTH),
                ("dwState", DWORD),
                ("dwStateMask", DWORD),
                ("szInfo", CHAR * SZINFO_MAX_LENGTH),
                ("uTimeout", UINT),
                #("uVersion", UINT),  # is employed only when Shell_NotifyIcon send an NIM_SETVERSION message
                ("szInfoTitle", CHAR * SZINFOTITLE_MAX_LENGTH),
                ("dwInfoFlags", DWORD),
                ("guidItem", GUID),
               ]
    if sys.getwindowsversion().major >= 5:
        _fields_.append(("hBalloonIcon", HICON))

def PackMENUITEMINFO(text=None, hbmpItem=None, wID=None, hSubMenu=None, fState=None, fType=None):
    res = MENUITEMINFO()
    res.cbSize = ctypes.sizeof(res)
    if fType is not None:
        res.fMask |= MIIM_FTYPE
        res.fType = fType
        if fType is MFT_SEPARATOR:
            return res
    if hbmpItem is not None:
        res.fMask |= MIIM_BITMAP
        res.hbmpItem = hbmpItem
    if wID is not None:
        res.fMask |= MIIM_ID
        res.wID = wID
    if text is not None:
        res.fMask |= MIIM_STRING
        res.dwTypeData = encode_for_locale(text)
    if hSubMenu is not None:
        res.fMask |= MIIM_SUBMENU
        res.hSubMenu = hSubMenu
    if fState is not None:
        res.fMask |= MIIM_STATE
        res.fState = fState
    return res

def LOWORD(w):
    return w & 0xFFFF

def PumpMessages():
    msg = MSG()
    while GetMessage(ctypes.byref(msg), None, 0, 0) > 0:
        TranslateMessage(ctypes.byref(msg))
        DispatchMessage(ctypes.byref(msg))

def NotifyData(hWnd=0, uID=0, uFlags=0, uCallbackMessage=0, hIcon=0, szTip="",
               szInfo="", szInfoTitle="", dwInfoFlags=0, uTimeout=15):
    res = NOTIFYICONDATA()
    res.cbSize = ctypes.sizeof(res)
    res.hWnd = hWnd
    res.uID = uID
    res.uFlags = uFlags
    if uCallbackMessage:
        res.uFlags |= NIF_MESSAGE
        res.uCallbackMessage = uCallbackMessage
    if hIcon:
        res.uFlags |= NIF_ICON
        res.hIcon = hIcon
    if szTip:
        res.uFlags |= NIF_TIP
        res.szTip = encode_for_locale(szTip)[:SZTIP_MAX_LENGTH]
    if szInfo or szInfoTitle:
        res.uFlags |= NIF_INFO
        res.szInfo = encode_for_locale(szInfo)[:SZINFO_MAX_LENGTH]
        res.szInfoTitle = encode_for_locale(szInfoTitle)[:SZINFOTITLE_MAX_LENGTH]
        res.dwInfoFlags = dwInfoFlags
        res.uTimeout = uTimeout
    return res
