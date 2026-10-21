// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
namespace citra_gateway {
// Requests, not autodetection or evidence that a real emulator matches this build.
enum class ApplicationMode { LegacyTransport, MhxxMhgu };
enum class ProxyWireProfile { Mirror01052024, Yuzu2022 };
inline const char* gateway_capability_error(ApplicationMode mode, ProxyWireProfile profile) noexcept {
    if (mode != ApplicationMode::LegacyTransport) return "gateway_application_mode_unavailable";
    if (profile != ProxyWireProfile::Mirror01052024) return "gateway_proxy_profile_unavailable";
    return nullptr;
}
inline constexpr char gateway_capabilities_json[] =
    R"({"schema":1,"defaultApplicationMode":"legacy-transport","proxyWireProfile":"yuzu-mirror-01052024","mhxxMhguApplicationConversion":false,"installedBinaryProfileVerified":false,"applicationConverted":false,"productionReady":false})";
} // namespace citra_gateway
