// SPDX-License-Identifier: GPL-2.0-or-later
#include "gateway_gui/settings.hpp"
#include <iostream>
int wmain(int argc, wchar_t** argv) {
    if (argc != 3) return 2;
    wchar_t absolute[32768]{};
    if (!GetFullPathNameW(argv[2], 32768, absolute, nullptr)) return 3;
    const std::wstring path = absolute, mode = argv[1];
    const auto value = gateway_gui::load_settings(path);
    if (mode == L"write") {
        if (!value.server.empty() || !value.server_port.empty() || value.local_port != L"8888" || !value.password.empty()) return 4;
        if (value.listen_address != L"127.0.0.1") return 11;
        if (!gateway_gui::save_settings(path, {L"example.test", L"24933", L"8889", L"测试 password 123", L"0.0.0.0"})) { std::cerr << "Save error: " << GetLastError() << '\n'; return 5; }
    } else if (mode == L"read-clear") {
        if (value.listen_address != L"0.0.0.0") return 12;
        if (!WritePrivateProfileStringW(L"Connection", L"ListenAddress", nullptr, path.c_str())) return 14;
        if (gateway_gui::load_settings(path).listen_address != L"127.0.0.1") return 15;
        if (value.server != L"example.test" || value.server_port != L"24933" || value.local_port != L"8889" || value.password != L"测试 password 123") return 6;
        if (!gateway_gui::save_settings(path, {L"", L"", L"", L""})) return 7;
    } else if (mode == L"read-empty") {
        if (value.listen_address != L"127.0.0.1") return 13;
        if (!value.server.empty() || !value.server_port.empty() || !value.local_port.empty() || !value.password.empty()) return 8;
        if (!DeleteFileW(path.c_str())) return 9;
    } else return 10;
    std::cout << "PASS settings process\n";
    return 0;
}
