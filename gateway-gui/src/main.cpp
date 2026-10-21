// SPDX-License-Identifier: GPL-2.0-or-later
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>
#include "gateway_gui/backend.hpp"
#include <limits>
#include <string>
#include <vector>

namespace {
constexpr int Connect = 101, Server = 102, RemotePort = 103, LocalPort = 104, Password = 105;
constexpr int MenuAbout = 200, LnkQQ = 201, LnkGroup = 202, LnkGithub = 203, AboutClose = 204;
constexpr wchar_t AppVersion[] = L"V335";
constexpr wchar_t GitHubUrl[] = L"https://github.com/caaaaaaaaaaaat/MHXX-GU-Gateway";
constexpr wchar_t QQNumber[] = L"1726956536";
constexpr wchar_t QQGroup[] = L"741115244";
gateway_gui::Backend backend;
HWND main_window, server_edit, remote_edit, local_edit, password_edit, button;
HWND heading, subtitle, state_text, count_text, endpoint_text, help_text;
std::vector<HWND> fields;
HWND about_window = nullptr, about_title, about_version, about_author,
    about_qq_label, about_qq, about_group_label, about_group,
    about_github_label, about_github, about_button;
int about_copied_id = 0;
HFONT font, title_font, state_font, link_font;
HBRUSH background;
bool closing = false;
bool smoke = false;
int scale = 96;
void smoke_log(const char* stage) {
    if (!smoke) return;
    wchar_t path[MAX_PATH]{};
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    std::wstring target(path);
    target = target.substr(0, target.find_last_of(L"\\/") + 1) + L"..\\ui-smoke.log";
    HANDLE file = CreateFileW(target.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        WriteFile(file, stage, static_cast<DWORD>(strlen(stage)), &written, nullptr);
        WriteFile(file, "\r\n", 2, &written, nullptr);
        CloseHandle(file);
    }
}
int px(int n) { return MulDiv(n, scale, 96); }
std::wstring wide(const std::string& s) {
    if (s.empty()) return {};
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring out(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), n);
    return out;
}
std::string utf8(const std::wstring& s) {
    const int n = WideCharToMultiByte(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0, nullptr, nullptr);
    std::string out(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), n, nullptr, nullptr);
    return out;
}
std::wstring text(HWND h) {
    std::wstring out(GetWindowTextLengthW(h) + 1, L'\0');
    const int n = GetWindowTextW(h, out.data(), static_cast<int>(out.size()));
    out.resize(n);
    return out;
}
void set(HWND h, const std::wstring& s) {
    if (text(h) != s) SetWindowTextW(h, s.c_str());
}
unsigned port(HWND h) {
    const auto s = text(h);
    if (s.empty() || s.size() > 5) return 0;
    unsigned n = 0;
    for (const auto ch : s) {
        if (ch < L'0' || ch > L'9') return 0;
        n = n * 10 + ch - L'0';
    }
    return n <= 65535 ? n : 0;
}
HWND control(const wchar_t* cls, const wchar_t* label, DWORD style, int id = 0) {
    HWND h = CreateWindowExW(wcscmp(cls, L"EDIT") == 0 ? WS_EX_CLIENTEDGE : 0,
        cls, label, WS_CHILD | WS_VISIBLE | style, 0, 0, 0, 0, main_window,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), GetModuleHandleW(nullptr), nullptr);
    SendMessageW(h, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
    return h;
}
void place(HWND h, int x, int y, int w, int ht) { MoveWindow(h, px(x), px(y), px(w), px(ht), TRUE); }
void layout() {
    RECT r{}; GetClientRect(main_window, &r);
    const int w = MulDiv(r.right, 96, scale);
    const int inner = w - 64;
    place(heading, 32, 23, inner, 36);
    place(subtitle, 32, 65, inner, 24);
    place(fields[0], 32, 111, inner - 160, 24);
    place(fields[1], w - 176, 111, 144, 24);
    place(server_edit, 32, 139, inner - 160, 32);
    place(remote_edit, w - 176, 139, 144, 32);
    place(fields[2], 32, 190, (inner - 16) / 2, 24);
    place(fields[3], 40 + (inner / 2), 190, (inner - 16) / 2, 24);
    place(local_edit, 32, 218, (inner - 16) / 2, 32);
    place(password_edit, 40 + (inner / 2), 218, (inner - 16) / 2, 32);
    place(button, 32, 276, 144, 38);
    place(count_text, 195, 281, inner - 163, 32);
    place(state_text, 32, 343, inner, 62);
    place(endpoint_text, 32, 413, inner, 32);
    place(help_text, 32, 463, inner, 98);
}
void update() {
    const auto v = backend.view();
    const bool active = backend.running();
    for (HWND h : {server_edit, remote_edit, local_edit, password_edit}) EnableWindow(h, !active && !closing);
    set(button, active ? L"停止网关" : L"启动网关");
    EnableWindow(button, !closing && v.phase != gateway_gui::Phase::Stopping);
    set(count_text, L"已接入 " + std::to_wstring(v.citra_count) + L" 台 Citra");
    set(state_text, v.detail.empty() ? L"网关未启动" : wide(v.detail));
    const bool listening = v.phase == gateway_gui::Phase::Listening ||
        v.phase == gateway_gui::Phase::Connecting || v.phase == gateway_gui::Phase::Connected;
    set(endpoint_text, listening ? L"Citra 连接地址：" + wide(v.endpoint) : L"Citra 连接地址：启动后显示");
    if (closing && !active) DestroyWindow(main_window);
}
void connect() {
    if (backend.running()) { backend.stop(); update(); return; }
    gateway_gui::Config config;
    config.server = utf8(text(server_edit));
    config.server_port = port(remote_edit);
    config.local_port = port(local_edit);
    config.password = utf8(text(password_edit));
    try { backend.start(std::move(config)); }
    catch (const std::exception& e) { MessageBoxW(main_window, wide(e.what()).c_str(), L"无法启动网关", MB_OK | MB_ICONWARNING); }
    update();
}
bool copy_clipboard(HWND owner, const std::wstring& value) {
    if (!OpenClipboard(owner)) return false;
    EmptyClipboard();
    const SIZE_T bytes = (value.size() + 1) * sizeof(wchar_t);
    HGLOBAL memory = GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (!memory) { CloseClipboard(); return false; }
    memcpy(GlobalLock(memory), value.c_str(), bytes);
    GlobalUnlock(memory);
    SetClipboardData(CF_UNICODETEXT, memory);
    CloseClipboard();
    return true;
}
void about_place(HWND h, int x, int y, int w, int ht) { MoveWindow(h, px(x), px(y), px(w), px(ht), TRUE); }
void about_layout(HWND window) {
    RECT r{}; GetClientRect(window, &r);
    const int w = MulDiv(r.right, 96, scale);
    const int value_x = 130, value_w = w - 28 - value_x;
    about_place(about_title, 28, 24, w - 56, 36);
    about_place(about_version, 28, 68, w - 56, 22);
    about_place(about_author, 28, 104, w - 56, 22);
    about_place(about_qq_label, 28, 138, 60, 26);
    about_place(about_qq, value_x, 138, value_w, 26);
    about_place(about_group_label, 28, 170, 100, 26);
    about_place(about_group, value_x, 170, value_w, 26);
    about_place(about_github_label, 28, 202, 75, 26);
    about_place(about_github, value_x, 202, value_w, 26);
    about_place(about_button, w / 2 - 60, 248, 120, 34);
}
LRESULT CALLBACK about_proc(HWND h, UINT message, WPARAM wp, LPARAM lp) {
    switch (message) {
    case WM_CREATE: {
        const HINSTANCE instance = GetModuleHandleW(nullptr);
        const auto make = [&h, &instance](const wchar_t* cls, const wchar_t* label, DWORD style,
                                          int id, HFONT f) {
            HWND control = CreateWindowExW(0, cls, label, WS_CHILD | WS_VISIBLE | style, 0, 0, 0, 0,
                h, id ? reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)) : nullptr, instance, nullptr);
            SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(f), TRUE);
            return control;
        };
        about_title = make(L"STATIC", L"MHXX/GU-Gateway", 0, 0, title_font);
        about_version = make(L"STATIC", (std::wstring(L"网关版本 ") + AppVersion).c_str(), 0, 0, font);
        about_author = make(L"STATIC", L"作者：小忆", 0, 0, font);
        about_qq_label = make(L"STATIC", L"QQ：", 0, 0, font);
        about_qq = make(L"STATIC", QQNumber, SS_NOTIFY, LnkQQ, link_font);
        about_group_label = make(L"STATIC", L"交流QQ群：", 0, 0, font);
        about_group = make(L"STATIC", QQGroup, SS_NOTIFY, LnkGroup, link_font);
        about_github_label = make(L"STATIC", L"GitHub：", 0, 0, font);
        about_github = make(L"STATIC", GitHubUrl, SS_NOTIFY, LnkGithub, link_font);
        about_button = make(L"BUTTON", L"关闭", WS_TABSTOP | BS_DEFPUSHBUTTON, AboutClose, font);
        about_layout(h);
        return 0;
    }
    case WM_SIZE: about_layout(h); return 0;
    case WM_CTLCOLORSTATIC: {
        const HDC dc = reinterpret_cast<HDC>(wp);
        const HWND source = reinterpret_cast<HWND>(lp);
        SetBkMode(dc, TRANSPARENT);
        if (source == about_qq || source == about_group || source == about_github)
            SetTextColor(dc, RGB(0, 102, 204));
        else
            SetTextColor(dc, RGB(35, 48, 65));
        return reinterpret_cast<LRESULT>(background);
    }
    case WM_SETCURSOR: {
        const HWND source = reinterpret_cast<HWND>(wp);
        if ((source == about_qq || source == about_group || source == about_github) && LOWORD(lp) == HTCLIENT) {
            SetCursor(LoadCursorW(nullptr, IDC_HAND));
            return TRUE;
        }
        break;
    }
    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case LnkQQ:
        case LnkGroup: {
            const bool qq = LOWORD(wp) == LnkQQ;
            if (copy_clipboard(h, qq ? QQNumber : QQGroup)) {
                about_copied_id = LOWORD(wp);
                SetWindowTextW(qq ? about_qq : about_group,
                    (std::wstring(qq ? QQNumber : QQGroup) + L"（已复制）").c_str());
                SetTimer(h, 1, 1000, nullptr);
            }
            return 0;
        }
        case LnkGithub:
            ShellExecuteW(nullptr, L"open", GitHubUrl, nullptr, nullptr, SW_SHOWNORMAL);
            return 0;
        case AboutClose:
            DestroyWindow(h);
            return 0;
        }
        return 0;
    case WM_TIMER:
        KillTimer(h, 1);
        if (about_copied_id == LnkQQ) SetWindowTextW(about_qq, QQNumber);
        else if (about_copied_id == LnkGroup) SetWindowTextW(about_group, QQGroup);
        about_copied_id = 0;
        return 0;
    case WM_CLOSE:
        DestroyWindow(h);
        return 0;
    case WM_DESTROY:
        about_window = nullptr;
        EnableWindow(main_window, TRUE);
        SetForegroundWindow(main_window);
        return 0;
    }
    return DefWindowProcW(h, message, wp, lp);
}
void show_about() {
    if (about_window) { SetForegroundWindow(about_window); return; }
    const HDC dc = GetDC(main_window);
    const HFONT old_font = reinterpret_cast<HFONT>(SelectObject(dc, link_font));
    SIZE url_size{};
    GetTextExtentPoint32W(dc, GitHubUrl, static_cast<int>(wcslen(GitHubUrl)), &url_size);
    SelectObject(dc, old_font);
    ReleaseDC(main_window, dc);
    const int url_logical = MulDiv(url_size.cx, 96, scale);
    const int wanted = 28 + 130 + url_logical + 28;
    const int client_w = wanted > 560 ? wanted : 560;
    RECT frame{0, 0, px(client_w), px(300)};
    AdjustWindowRectEx(&frame, WS_POPUP | WS_CAPTION | WS_SYSMENU, FALSE, WS_EX_CONTROLPARENT);
    const int width = frame.right - frame.left, height = frame.bottom - frame.top;
    RECT owner{}; GetWindowRect(main_window, &owner);
    int x = owner.left + ((owner.right - owner.left) - width) / 2;
    int y = owner.top + ((owner.bottom - owner.top) - height) / 2;
    if (x < 0) x = 0;
    if (y < 0) y = 0;
    EnableWindow(main_window, FALSE);
    about_window = CreateWindowExW(WS_EX_CONTROLPARENT, L"XXGUAboutBox", L"关于 XXGU 联机网关",
        WS_POPUP | WS_CAPTION | WS_SYSMENU, x, y, width, height, main_window, nullptr,
        GetModuleHandleW(nullptr), nullptr);
    ShowWindow(about_window, SW_SHOW);
    UpdateWindow(about_window);
}
LRESULT CALLBACK proc(HWND h, UINT message, WPARAM wp, LPARAM lp) {
    switch (message) {
    case WM_CREATE: {
        smoke_log("WM_CREATE begin");
        main_window = h;
        const HDC dc = GetDC(h); scale = GetDeviceCaps(dc, LOGPIXELSX); ReleaseDC(h, dc);
        font = CreateFontW(-px(15), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Microsoft YaHei UI");
        title_font = CreateFontW(-px(25), 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Microsoft YaHei UI");
        state_font = CreateFontW(-px(18), 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Microsoft YaHei UI");
        link_font = CreateFontW(-px(15), 0, 0, 0, FW_SEMIBOLD, FALSE, TRUE, FALSE, DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Microsoft YaHei UI");
        heading = control(L"STATIC", L"XXGU 联机网关", 0);
        SendMessageW(heading, WM_SETFONT, reinterpret_cast<WPARAM>(title_font), TRUE);
        subtitle = control(L"STATIC", L"连接 Yuzu 房间，让 Citra 一起联机", 0);
        for (const wchar_t* label : {L"服务器地址", L"服务器 UDP 端口", L"本机 Citra 接入端口", L"房间密码（可选）"})
            fields.push_back(control(L"STATIC", label, 0));
        server_edit = control(L"EDIT", L"127.0.0.1", WS_TABSTOP | ES_AUTOHSCROLL, Server);
        remote_edit = control(L"EDIT", L"24872", WS_TABSTOP | ES_NUMBER | ES_AUTOHSCROLL, RemotePort);
        local_edit = control(L"EDIT", L"24875", WS_TABSTOP | ES_NUMBER | ES_AUTOHSCROLL, LocalPort);
        password_edit = control(L"EDIT", L"", WS_TABSTOP | ES_PASSWORD | ES_AUTOHSCROLL, Password);
        SendMessageW(server_edit, EM_SETLIMITTEXT, 253, 0);
        SendMessageW(remote_edit, EM_SETLIMITTEXT, 5, 0);
        SendMessageW(local_edit, EM_SETLIMITTEXT, 5, 0);
        SendMessageW(password_edit, EM_SETLIMITTEXT, 4096, 0);
        button = control(L"BUTTON", L"启动网关", WS_TABSTOP | BS_DEFPUSHBUTTON, Connect);
        count_text = control(L"STATIC", L"已接入 0 台 Citra", 0);
        state_text = control(L"STATIC", L"网关未启动", 0);
        SendMessageW(state_text, WM_SETFONT, reinterpret_cast<WPARAM>(state_font), TRUE);
        endpoint_text = control(L"STATIC", L"Citra 连接地址：启动后显示", 0);
        help_text = control(L"STATIC", L"1. 填写 Yuzu 房间服务器地址、端口及密码，启动网关。\r\n2. Citra 直连上方本机地址，并填写同一个房间密码。\r\n3. Yuzu 直接加入服务器；多台本机 Citra 可共用此网关。\r\n请在联机期间保持此窗口开启。", 0);
        SetTimer(h, 1, 200, nullptr);
        layout();
        smoke_log("WM_CREATE complete");
        return 0;
    }
    case WM_SIZE: layout(); return 0;
    case WM_GETMINMAXINFO: {
        auto* info = reinterpret_cast<MINMAXINFO*>(lp);
        info->ptMinTrackSize = {px(640), px(630) + GetSystemMetrics(SM_CYMENU)}; return 0;
    }
    case WM_CTLCOLORSTATIC: {
        SetBkMode(reinterpret_cast<HDC>(wp), TRANSPARENT);
        SetTextColor(reinterpret_cast<HDC>(wp), RGB(35, 48, 65));
        return reinterpret_cast<LRESULT>(background);
    }
    case WM_COMMAND:
        if (LOWORD(wp) == MenuAbout) show_about();
        if (LOWORD(wp) == Connect && HIWORD(wp) == BN_CLICKED) connect();
        return 0;
    case WM_TIMER:
        smoke_log("WM_TIMER");
        update();
        if (smoke) PostMessageW(h, WM_CLOSE, 0, 0);
        return 0;
    case WM_CLOSE:
        smoke_log("WM_CLOSE");
        closing = true; backend.stop(); update(); return 0;
    case WM_DESTROY:
        smoke_log("WM_DESTROY");
        KillTimer(h, 1);
        DeleteObject(font); DeleteObject(title_font); DeleteObject(state_font); DeleteObject(link_font);
        PostQuitMessage(0); return 0;
    }
    return DefWindowProcW(h, message, wp, lp);
}
}
int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR command, int show) {
    (void)command;
    smoke = wcsstr(GetCommandLineW(), L"--smoke-test") != nullptr;
    smoke_log("wWinMain");
    SetProcessDPIAware();
    INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_STANDARD_CLASSES}; InitCommonControlsEx(&controls);
    background = CreateSolidBrush(RGB(247, 249, 252));
    const HICON app_icon = LoadIconW(instance, MAKEINTRESOURCEW(1));
    WNDCLASSEXW cls{}; cls.cbSize = sizeof(cls); cls.hInstance = instance;
    cls.lpfnWndProc = proc; cls.lpszClassName = L"XXGUGatewayDesktop";
    cls.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    cls.hIcon = app_icon; cls.hIconSm = app_icon; cls.hbrBackground = background;
    if (!RegisterClassExW(&cls)) return 1;
    WNDCLASSEXW about_cls{}; about_cls.cbSize = sizeof(about_cls); about_cls.hInstance = instance;
    about_cls.lpfnWndProc = about_proc; about_cls.lpszClassName = L"XXGUAboutBox";
    about_cls.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    about_cls.hIcon = app_icon; about_cls.hIconSm = app_icon; about_cls.hbrBackground = background;
    if (!RegisterClassExW(&about_cls)) return 1;
    HMENU bar = CreateMenu();
    AppendMenuW(bar, MF_STRING, MenuAbout, L"关于");
    HWND h = CreateWindowExW(WS_EX_CONTROLPARENT, cls.lpszClassName,
        (std::wstring(L"XXGU 联机网关 · ") + AppVersion).c_str(),
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_THICKFRAME,
        CW_USEDEFAULT, CW_USEDEFAULT, 740, 670, nullptr, bar, instance, nullptr);
    if (!h) return 2;
    RECT desired{0, 0, px(700), px(590)};
    AdjustWindowRectEx(&desired, static_cast<DWORD>(GetWindowLongPtrW(h, GWL_STYLE)), FALSE, WS_EX_CONTROLPARENT);
    desired.bottom += GetSystemMetrics(SM_CYMENU);
    SetWindowPos(h, nullptr, 0, 0, desired.right - desired.left, desired.bottom - desired.top, SWP_NOMOVE | SWP_NOZORDER);
    smoke_log("window created");
    if (!smoke) ShowWindow(h, show);
    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        if (!IsDialogMessageW(about_window ? about_window : h, &msg)) { TranslateMessage(&msg); DispatchMessageW(&msg); }
    }
    DeleteObject(background);
    smoke_log("message loop complete");
    return static_cast<int>(msg.wParam);
}
