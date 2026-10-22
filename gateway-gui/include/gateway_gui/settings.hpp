// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
#include <windows.h>
#include <wincrypt.h>
#include <shlobj.h>
#include <string>
#include <vector>

namespace gateway_gui {
struct Settings {
    std::wstring server, server_port, local_port = L"8888", password;
    std::wstring listen_address = L"127.0.0.1";
};
inline std::wstring settings_path() {
    wchar_t base[MAX_PATH]{};
    if (FAILED(SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA | CSIDL_FLAG_CREATE,
                              nullptr, SHGFP_TYPE_CURRENT, base))) return {};
    const auto directory = std::wstring(base) + L"\\XXGU-Gateway";
    if (!CreateDirectoryW(directory.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS) return {};
    return directory + L"\\settings.ini";
}
inline Settings load_settings(const std::wstring& path) {
    Settings result;
    if (path.empty()) return result;
    const auto read = [&](const wchar_t* key, const wchar_t* fallback) {
        std::vector<wchar_t> buffer(32768);
        GetPrivateProfileStringW(L"Connection", key, fallback, buffer.data(),
                                 static_cast<DWORD>(buffer.size()), path.c_str());
        return std::wstring(buffer.data());
    };
    result.server = read(L"Server", L"");
    result.listen_address = read(L"ListenAddress", L"127.0.0.1");
    result.server_port = read(L"ServerPort", L"");
    result.local_port = read(L"LocalPort", L"8888");
    const auto encrypted = read(L"PasswordEncrypted", L"");
    std::vector<BYTE> bytes;
    const auto nibble = [](wchar_t c) -> int {
        if (c >= L'0' && c <= L'9') return c - L'0';
        if (c >= L'a' && c <= L'f') return c - L'a' + 10;
        return -1;
    };
    if (!encrypted.empty() && encrypted.size() % 2 == 0) {
        for (size_t i = 0; i < encrypted.size(); i += 2) {
            int a = nibble(encrypted[i]), b = nibble(encrypted[i + 1]);
            if (a < 0 || b < 0) { bytes.clear(); break; }
            bytes.push_back(static_cast<BYTE>(a * 16 + b));
        }
    }
    if (!bytes.empty()) {
        DATA_BLOB input{static_cast<DWORD>(bytes.size()), bytes.data()}, plain{};
        if (CryptUnprotectData(&input, nullptr, nullptr, nullptr, nullptr,
                               CRYPTPROTECT_UI_FORBIDDEN, &plain)) {
            if (plain.cbData % sizeof(wchar_t) == 0)
                result.password.assign(reinterpret_cast<wchar_t*>(plain.pbData), plain.cbData / sizeof(wchar_t));
            SecureZeroMemory(plain.pbData, plain.cbData);
            LocalFree(plain.pbData);
        }
    }
    return result;
}
inline bool save_settings(const std::wstring& path, const Settings& settings) {
    if (path.empty()) return false;
    std::wstring password;
    if (!settings.password.empty()) {
        DATA_BLOB input{static_cast<DWORD>(settings.password.size() * sizeof(wchar_t)),
                        reinterpret_cast<BYTE*>(const_cast<wchar_t*>(settings.password.data()))}, encrypted{};
        if (!CryptProtectData(&input, L"XXGU Gateway password", nullptr, nullptr, nullptr,
                              CRYPTPROTECT_UI_FORBIDDEN, &encrypted)) return false;
        for (DWORD i = 0; i < encrypted.cbData; ++i) {
            password += L"0123456789abcdef"[encrypted.pbData[i] >> 4];
            password += L"0123456789abcdef"[encrypted.pbData[i] & 15];
        }
        LocalFree(encrypted.pbData);
    }
    // A UTF-16 BOM makes the Windows profile APIs preserve Unicode hostnames.
    HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                              CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file != INVALID_HANDLE_VALUE) {
        const WORD bom = 0xfeff; DWORD written = 0;
        const bool ok = WriteFile(file, &bom, sizeof(bom), &written, nullptr) && written == sizeof(bom);
        CloseHandle(file);
        if (!ok) return false;
    }
    bool ok = true;
    for (const auto& pair : std::vector<std::pair<const wchar_t*, std::wstring>>{
        {L"Server", settings.server}, {L"ServerPort", settings.server_port},
        {L"ListenAddress", settings.listen_address},
        {L"LocalPort", settings.local_port}, {L"PasswordEncrypted", password}})
        ok = WritePrivateProfileStringW(L"Connection", pair.first, pair.second.c_str(), path.c_str()) && ok;
    WritePrivateProfileStringW(nullptr, nullptr, nullptr, path.c_str());
    return ok;
}
} // namespace gateway_gui
