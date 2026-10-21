// SPDX-License-Identifier: GPL-3.0-or-later
// citra-control - prints the compile-time-asserted sizeof/offsetof values.
#include <cstdio>

#include "citra_control/mirrors.hpp"
#include "harness.hpp"

using namespace citra_control::mirror;

TT_SUITE(mirrors) {
    TT_CASE();
    std::printf("  MIRROR citra BeaconEntryHeader sizeof=0x%zX\n", sizeof(citra::BeaconEntryHeader));
    std::printf("  MIRROR citra BeaconFrameHeader sizeof=%zu\n", sizeof(citra::BeaconFrameHeader));
    std::printf("  MIRROR citra NetworkInfoTag sizeof=%zu network_info@0x%zX sha_hash@0x%zX appdata_size@0x%zX\n",
                sizeof(citra::NetworkInfoTag), offsetof(citra::NetworkInfoTag, network_info),
                offsetof(citra::NetworkInfoTag, sha_hash), offsetof(citra::NetworkInfoTag, appdata_size));
    std::printf("  MIRROR citra BeaconDataCryptoCTR sizeof=0x%zX wlan_comm_id@%zu network_id@%zu\n",
                sizeof(citra::BeaconDataCryptoCTR), offsetof(citra::BeaconDataCryptoCTR, wlan_comm_id),
                offsetof(citra::BeaconDataCryptoCTR, network_id));
    std::printf("  MIRROR citra BeaconNodeInfo sizeof=0x%zX network_node_id@0x%zX\n", sizeof(citra::BeaconNodeInfo),
                offsetof(citra::BeaconNodeInfo, network_node_id));
    std::printf("  MIRROR citra EAPoLNodeInfo sizeof=0x%zX network_node_id@0x%zX\n", sizeof(citra::EAPoLNodeInfo),
                offsetof(citra::EAPoLNodeInfo, network_node_id));
    std::printf("  MIRROR citra EAPoLStartPacket sizeof=0x%zX node@0x%zX\n", sizeof(citra::EAPoLStartPacket),
                offsetof(citra::EAPoLStartPacket, node));
    std::printf("  MIRROR citra EAPoLLogoffPacket sizeof=0x%zX nodes@0x%zX\n", sizeof(citra::EAPoLLogoffPacket),
                offsetof(citra::EAPoLLogoffPacket, nodes));
    std::printf("  MIRROR citra GuestNodeInfo sizeof=0x%zX network_node_id@0x%zX\n", sizeof(citra::GuestNodeInfo),
                offsetof(citra::GuestNodeInfo, network_node_id));
    std::printf("  MIRROR citra GuestNetworkInfo sizeof=0x%zX oui_value@0x%zX wlan_comm_id@0x%zX appdata@0x%zX\n",
                sizeof(citra::GuestNetworkInfo), offsetof(citra::GuestNetworkInfo, oui_value),
                offsetof(citra::GuestNetworkInfo, wlan_comm_id), offsetof(citra::GuestNetworkInfo, application_data));
    std::printf("  MIRROR citra ConnectionStatus sizeof=0x%zX nodes@0x%zX bitmask@0x%zX\n",
                sizeof(citra::ConnectionStatusMirror), offsetof(citra::ConnectionStatusMirror, nodes),
                offsetof(citra::ConnectionStatusMirror, node_bitmask));
    std::printf("  MIRROR citra SecureDataHeader sizeof=%zu protocol_size@0 securedata_size@%zu\n",
                sizeof(citra::SecureDataHeader), offsetof(citra::SecureDataHeader, securedata_size));
    std::printf("  MIRROR yuzu SessionId sizeof=0x%zX IntentId sizeof=0x%zX NetworkId sizeof=0x%zX\n",
                sizeof(yuzu::SessionId), sizeof(yuzu::IntentId), sizeof(yuzu::NetworkId));
    std::printf("  MIRROR yuzu Ssid sizeof=0x%zX CommonNetworkInfo sizeof=0x%zX channel@0x%zX\n", sizeof(yuzu::Ssid),
                sizeof(yuzu::CommonNetworkInfo), offsetof(yuzu::CommonNetworkInfo, channel));
    std::printf("  MIRROR yuzu NodeInfo sizeof=0x%zX node_id@0x%zX user_name@0x%zX\n", sizeof(yuzu::NodeInfo),
                offsetof(yuzu::NodeInfo, node_id), offsetof(yuzu::NodeInfo, user_name));
    std::printf("  MIRROR yuzu LdnNetworkInfo sizeof=0x%zX nodes@0x%zX advertise_data_size@0x%zX advertise_data@0x%zX\n",
                sizeof(yuzu::LdnNetworkInfo), offsetof(yuzu::LdnNetworkInfo, nodes),
                offsetof(yuzu::LdnNetworkInfo, advertise_data_size), offsetof(yuzu::LdnNetworkInfo, advertise_data));
    std::printf("  MIRROR yuzu NetworkInfo sizeof=0x%zX common@0x%zX ldn@0x%zX\n", sizeof(yuzu::NetworkInfo),
                offsetof(yuzu::NetworkInfo, common), offsetof(yuzu::NetworkInfo, ldn));
    TT_CHECK(sizeof(citra::GuestNetworkInfo) == 0x108);
    TT_CHECK(sizeof(citra::GuestNodeInfo) == 40);
    TT_CHECK(sizeof(citra::ConnectionStatusMirror) == 0x30);
    TT_CHECK(sizeof(citra::EAPoLStartPacket) == 0x30);
    TT_CHECK(sizeof(citra::EAPoLLogoffPacket) == 0x298);
    TT_CHECK(sizeof(yuzu::NodeInfo) == 0x40);
    TT_CHECK(sizeof(yuzu::NetworkInfo) == 0x480);
}
