import os
from .win32_adapter import *
import threading

class SysTrayIcon(object):
    """
    menu_options: sequence of sequences
    action = function or special action text or sub_menu_options
    (menu text, action) or
    (menu text, action, icon path) or
    (menu text, action, icon path, fState) or
    (menu text, action, icon path, fState, fType) or
    (menu text, action, fState) or
    (menu text, action, fState, fType) or
    (menu text, action, fState, icon path) or
    (menu text, action, fState, fType, icon path)

    menu text and tray hover text should be Unicode
    hover_text length is limited to 128; longer text will be truncated

    Can be used as context manager to enable automatic termination of tray
    if parent thread is closed:

        with SysTrayIcon(icon, hover_text) as systray:
            for item in ['item1', 'item2', 'item3']:
                systray.update(hover_text=item)
                do_something(item)

    """
    QUIT = 'QUIT'
    SEPARATOR = '-'
    PASS = 'pass'
    SPECIAL_ACTIONS = [QUIT, SEPARATOR, PASS]
    _quit_text = QUIT
    _quit_icon = None
    _on_quit = None

    FIRST_ID = 1023

    def __init__(self,
                 icon,
                 hover_text,
                 menu_options=None,
                 quit_item=None,
                 default_menu_index=None,
                 window_class_name=None,
                 left_click=None,
                 right_click=None):

        self._icon = icon
        self._icon_shared = False
        self._hover_text = hover_text
        if isinstance(quit_item, tuple):
            option_count = len(quit_item)
            if option_count == 1:
                self._quit_text, = quit_item
            elif option_count == 2:
                self._quit_text, self._on_quit = quit_item
            elif option_count == 3:
                self._quit_text, self._on_quit, self._quit_icon = quit_item
        self._quit_item = self._quit_text, SysTrayIcon.QUIT, self._quit_icon, None, None
        self._left_click = left_click
        self._right_click = right_click

        self._set_menu_options(menu_options)

        window_class_name = window_class_name or ("SysTrayIconPy-%s" % hover_text)

        self._default_menu_index = (default_menu_index or 0)
        self._window_class_name = encode_for_locale(window_class_name)
        self._message_dict = {RegisterWindowMessage(LPCSTR(b"TaskbarCreated")): self._restart,
                              WM_DESTROY: self._destroy,
                              WM_CLOSE: self._destroy,
                              WM_COMMAND: self._command,
                              WM_USER+20: self._notify}
        self._notify_id = None
        self._message_loop_thread = None
        self._hwnd = None
        self._hicon = 0
        self._hinst = None
        self._window_class = None
        self._menu = None
        self._balloons = ()
        self._register_class()

    def __enter__(self):
        """Context manager so SysTray can automatically close"""
        self.start()
        return self

    def __exit__(self, *args):
        """Context manager so SysTray can automatically close"""
        self.shutdown()

    def WndProc(self, hwnd, msg, wparam, lparam):
        hwnd = HANDLE(hwnd)
        wparam = WPARAM(wparam)
        lparam = LPARAM(lparam)
        if msg in self._message_dict:
            self._message_dict[msg](hwnd, msg, wparam.value, lparam.value)
        return DefWindowProc(hwnd, msg, wparam, lparam)

    def _register_class(self):
        # Register the Window class.
        self._window_class = WNDCLASS()
        self._hinst = self._window_class.hInstance = GetModuleHandle(None)
        self._window_class.lpszClassName = self._window_class_name
        self._window_class.style = CS_VREDRAW | CS_HREDRAW
        self._window_class.hCursor = LoadCursor(0, IDC_ARROW)
        self._window_class.hbrBackground = COLOR_WINDOW
        self._window_class.lpfnWndProc = WNDPROC(self.WndProc)
        RegisterClass(ctypes.byref(self._window_class))

    def _create_window(self):
        style = WS_OVERLAPPED | WS_SYSMENU
        self._hwnd = CreateWindowEx(0, self._window_class_name,
                                      self._window_class_name,
                                      style,
                                      0,
                                      0,
                                      CW_USEDEFAULT,
                                      CW_USEDEFAULT,
                                      0,
                                      0,
                                      self._hinst,
                                      None)
        UpdateWindow(self._hwnd)
        self._refresh_icon()

    def _message_loop_func(self):
        self._create_window()
        PumpMessages()

    def start(self, daemon=False):
        if self._hwnd:
            return      # already started
        self._message_loop_thread = threading.Thread(target=self._message_loop_func)
        self._message_loop_thread.daemon = daemon
        self._message_loop_thread.start()

    def shutdown(self):
        if not self._hwnd:
            return      # not started
        PostMessage(self._hwnd, WM_CLOSE, 0, 0)
        self._message_loop_thread.join()

    def update(self, icon=None, hover_text=None, menu=None):
        """ update icon image and/or hover text """
        if icon:
            self._icon = icon
            self._load_icon()
        if hover_text:
            self._hover_text = hover_text
        if menu:
            self._set_menu_options(menu)
            self._menu = CreatePopupMenu()
            self._create_menu(self._menu, self._menu_options)
        self._refresh_icon()

    def _set_menu_options(self, menu_options):
        menu_options = menu_options or ()
        self._next_action_id = SysTrayIcon.FIRST_ID
        self._menu_actions_by_id = set()
        self._menu_options = self._add_ids_to_menu_options(menu_options)
        self._menu_options.append((*self._quit_item, self._next_action_id))
        self._menu_actions_by_id.add((self._next_action_id, SysTrayIcon.QUIT))
        self._menu_actions_by_id = dict(self._menu_actions_by_id)

    def _add_ids_to_menu_options(self, menu_options):
        result = []
        menu_options = format_menu_options(menu_options)
        for menu_option in menu_options:
            option_text, option_action, option_icon, option_fState, option_fType = menu_option
            if callable(option_action) or option_action in SysTrayIcon.SPECIAL_ACTIONS:
                self._menu_actions_by_id.add((self._next_action_id, option_action))
                result.append((*menu_option, self._next_action_id))
            elif non_string_iterable(option_action):
                result.append((option_text,
                               self._add_ids_to_menu_options(option_action),
                               option_icon,
                               option_fState,
                               option_fType,
                               self._next_action_id))
            else:
                raise Exception('Unknown item', menu_option)
            self._next_action_id += 1
        return result

    def _load_icon(self):
        # release previous icon, if a custom one was loaded
        # note: it's important *not* to release the icon if we loaded the default system icon (with
        # the LoadIcon function) - this is why we assign self._hicon only if it was loaded using LoadImage
        if not self._icon_shared and self._hicon != 0:
            DestroyIcon(self._hicon)
            self._hicon = 0

        # Try and find a custom icon
        hicon = 0
        if self._icon is not None and os.path.isfile(self._icon):
            icon_flags = LR_LOADFROMFILE | LR_DEFAULTSIZE
            icon = encode_for_locale(self._icon)
            hicon = self._hicon = LoadImage(0, icon, IMAGE_ICON, 0, 0, icon_flags)
            self._icon_shared = False

        # Can't find icon file - using default shared icon
        if hicon == 0:
            self._hicon = LoadIcon(0, IDI_APPLICATION)
            self._icon_shared = True
            self._icon = None

    def _refresh_icon(self):
        if self._hwnd is None:
            return
        if self._hicon == 0:
            self._load_icon()
        if self._notify_id:
            message = NIM_MODIFY
        else:
            message = NIM_ADD
        self._notify_id = NotifyData(
                          self._hwnd,
                          0,
                          NIF_ICON | NIF_MESSAGE | NIF_TIP,
                          WM_USER+20,
                          self._hicon,
                          self._hover_text,
                          *self._balloons)
        Shell_NotifyIcon(message, ctypes.byref(self._notify_id))

    def show_balloon(self, info="", title="", flags=0, timeout=15):
        if info or title:
            self._balloons = info, title, flags, timeout
            self._refresh_icon()
            self._balloons = ()

    def _restart(self, hwnd, msg, wparam, lparam):
        self._notify_id = None
        self._refresh_icon()

    def _destroy(self, hwnd, msg, wparam, lparam):
        if self._notify_id:
            Shell_NotifyIcon(NIM_DELETE, ctypes.byref(self._notify_id))
        if self._on_quit:
            self._on_quit(self)
        PostQuitMessage(0)  # Terminate the app.
        # TODO * release self._menu with DestroyMenu and reset the memeber
        #      * release self._hicon with DestoryIcon and reset the member
        #      * release loaded menu icons (loaded in _load_menu_icon) with DeleteObject
        #        (we don't keep those objects anywhere now)
        self._hwnd = None
        self._notify_id = None

    def _notify(self, hwnd, msg, wparam, lparam):
        if lparam == WM_LBUTTONDBLCLK:
            self._execute_menu_option(self._default_menu_index + SysTrayIcon.FIRST_ID)
        elif lparam == WM_RBUTTONUP:
            if self._right_click is None:
                self._show_menu()
            else:
                self._right_click(self)
        elif lparam == WM_LBUTTONUP:
            if self._left_click is None:
                self._show_menu()
            else:
                self._left_click(self)
        return True

    def _show_menu(self):
        if self._menu is None:
            self._menu = CreatePopupMenu()
            self._create_menu(self._menu, self._menu_options)
            #SetMenuDefaultItem(self._menu, 1000, 0)

        pos = POINT()
        GetCursorPos(ctypes.byref(pos))
        # See http://msdn.microsoft.com/library/default.asp?url=/library/en-us/winui/menus_0hdi.asp
        SetForegroundWindow(self._hwnd)
        TrackPopupMenu(self._menu,
                       TPM_LEFTALIGN,
                       pos.x,
                       pos.y,
                       0,
                       self._hwnd,
                       None)
        PostMessage(self._hwnd, WM_NULL, 0, 0)

    def _create_menu(self, menu, menu_options):
        for option_text, option_action, option_icon, option_fState, option_fType, option_id in menu_options[::-1]:
            if option_icon:
                option_icon = self._prep_menu_icon(option_icon)

            if option_id in self._menu_actions_by_id:
                if option_action is SysTrayIcon.SEPARATOR:
                    option_text = None
                    option_icon = None
                    option_id = None
                    option_fState = None
                    option_fType = MFT_SEPARATOR
                item = PackMENUITEMINFO(text=option_text,
                                        hbmpItem=option_icon,
                                        wID=option_id,
                                        fState=option_fState,
                                        fType=option_fType)
            else:
                submenu = CreatePopupMenu()
                self._create_menu(submenu, option_action)
                item = PackMENUITEMINFO(text=option_text,
                                        hbmpItem=option_icon,
                                        hSubMenu=submenu,
                                        fState=option_fState,
                                        fType=option_fType)
            InsertMenuItem(menu, 0, 1,  ctypes.byref(item))

    def _prep_menu_icon(self, icon):
        icon = encode_for_locale(icon)
        # First load the icon.
        ico_x = GetSystemMetrics(SM_CXSMICON)
        ico_y = GetSystemMetrics(SM_CYSMICON)
        hicon = LoadImage(0, icon, IMAGE_ICON, ico_x, ico_y, LR_LOADFROMFILE)

        hdcBitmap = CreateCompatibleDC(None)
        hdcScreen = GetDC(None)
        hbm = CreateCompatibleBitmap(hdcScreen, ico_x, ico_y)
        hbmOld = SelectObject(hdcBitmap, hbm)
        # Fill the background.
        brush = GetSysColorBrush(COLOR_MENU)
        FillRect(hdcBitmap, ctypes.byref(RECT(0, 0, 16, 16)), brush)
        # draw the icon
        DrawIconEx(hdcBitmap, 0, 0, hicon, ico_x, ico_y, 0, 0, DI_NORMAL)
        SelectObject(hdcBitmap, hbmOld)

        # No need to free the brush
        DeleteDC(hdcBitmap)
        DestroyIcon(hicon)

        return hbm

    def _command(self, hwnd, msg, wparam, lparam):
        id = LOWORD(wparam)
        self._execute_menu_option(id)

    def _execute_menu_option(self, id):
        menu_action = self._menu_actions_by_id[id]
        if menu_action == SysTrayIcon.QUIT:
            DestroyWindow(self._hwnd)
        elif menu_action == SysTrayIcon.PASS:
            pass
        else:
            threading._start_new_thread(menu_action, (self,))

def non_string_iterable(obj):
    try:
        iter(obj)
    except TypeError:
        return False
    else:
        return not isinstance(obj, str)

class MenuOtionsError(Exception):

    def __init__(self, msg=''):
        self.msg = msg
        Exception.__init__(self, msg)

    def __str__(self):
        return self.msg

    def __repr__(self):
        return '%s: %s' % (self.__class__.__name__, self.msg)

class format_menu_options:

    def __init__(self, menu_options):
        if isinstance(menu_options, str):
            raise MenuOtionsError('menu options can not be a str object.')
        self.menu_options = menu_options

    def __iter__(self):
        try:
            for menu_option in self.menu_options:
                option_count = len(menu_option)
                if option_count < 2:
                    raise MenuOtionsError('requires at least 2 options'
                                          ' per menu item, got %d: %s.'
                                          % (option_count, menu_option))
                if option_count > 5:
                    raise MenuOtionsError('requires at most 5 options'
                                          ' per menu item, got %d: %s.'
                                          % (option_count, menu_option))
                if option_count == 2:
                    opt1, opt2 = menu_option
                    yield(opt1, opt2, None, None, None)
                if option_count == 3:
                    opt1, opt2, opt3 = menu_option
                    if isinstance(opt3, str):
                        yield(opt1, opt2, opt3, None, None)
                    elif isinstance(opt3, int):
                        yield(opt1, opt2, None, opt3, None)
                    else:
                        raise MenuOtionsError('the last menu option'
                                              ' can not be a %s object: %s'
                                            % (opt3.__class__.__name__,
                                               menu_option))
                elif option_count == 4:
                    opt1, opt2, opt3, opt4 = menu_option
                    if isinstance(opt3, str) and isinstance(opt4, int):
                        yield(opt1, opt2, opt3, opt4, None)
                    elif isinstance(opt3, int) and isinstance(opt4, str):
                        yield(opt1, opt2, opt4, opt3, None)
                    elif isinstance(opt3, int) and isinstance(opt4, int):
                        yield(opt1, opt2, None, opt3, opt4)
                    else:
                        raise MenuOtionsError('the last 2 menu options\'s'
                                              ' type [%s, %s] is wrong: %s'
                                            % (opt3.__class__.__name__,
                                               opt4.__class__.__name__,
                                               menu_option))
                elif option_count == 5:
                    opt1, opt2, opt3, opt4, opt5 = menu_option
                    if isinstance(opt3, str) and isinstance(opt4, int) and isinstance(opt5, int):
                        yield(opt1, opt2, opt3, opt4, opt5)
                    elif isinstance(opt3, int) and isinstance(opt4, int) and isinstance(opt5, str):
                        yield(opt1, opt2, opt5, opt3, opt4)
                    else:
                        raise MenuOtionsError('the last 3 menu options\'s'
                                              ' type [%s, %s, %s] is wrong: %s'
                                            % (opt3.__class__.__name__,
                                               opt4.__class__.__name__,
                                               opt5.__class__.__name__,
                                               menu_option))
        except TypeError:
            raise MenuOtionsError('menu options can not be a %s object.'
                                  % self.menu_options.__class__.__name__)
