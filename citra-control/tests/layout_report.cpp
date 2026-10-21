// SPDX-License-Identifier: GPL-3.0-or-later
// citra-control - printable layout report.
//
// mirrors.hpp carries the compile-time static_asserts for every mirrored Citra
// and Yuzu structure (sizeof + offsetof).  This program prints the same numbers
// so they can be pasted into docs/citra-control-report.md as evidence that the
// assertions were checked by the compiler with -Werror enabled.

#include <cstddef>
#include <cstdio>

#include "citra_control/ldn_ctrl.hpp"
#include "citra_control/mirrors.hpp"
#include "citra_control/uds_frames.hpp"

namespace mc = citra_control::mirror::citra;
namespace my = citra_control::mirror::yuzu;

using citra_control::kApplicationDataSize;
using citra_control::kConnectionStatusSize;
using citra_control::kEncryptedDataSizeCutoff;
using citra_control::kEapolLogoffPacketSize;
using citra_control::kEapolNodeInfoSize;
using citra_control::kEapolStartPacketSize;
using citra_control::kGuestNetworkInfoSize;
using citra_control::kGuestNodeInfoSize;
using citra_control::kLdnAdvertiseDataOffset;
using citra_control::kLdnAdvertiseDataSizeMax;
using citra_control::kLdnAdvertiseDataSizeOffset;
using citra_control::kLdnNetworkInfoSize;
using citra_control::kLdnNodeCountMax;
using citra_control::kLdnNodeInfoSize;
using citra_control::kLdnRandomAuthIdOffset;
using citra_control::kUdsMaxNodes;
using citra_control::ldn_body_size;
using citra_control::LdnPacketType;

#define P(expr) \
    std::printf("%-62s = 0x%zX (%zu)\n", #expr, static_cast<std::size_t>(expr), static_cast<std::size_t>(expr))

int main() {
    std::printf("-- citra (nwm) mirrors --\n");
    P(sizeof(mc::BeaconEntryHeader));
    P(offsetof(mc::BeaconEntryHeader, mac));
    P(sizeof(mc::BeaconFrameHeader));
    P(sizeof(mc::TagHeader));
    P(sizeof(mc::DummyTag));
    P(offsetof(mc::DummyTag, oui_type));
    P(sizeof(mc::NetworkInfoTag));
    P(offsetof(mc::NetworkInfoTag, network_info));
    P(offsetof(mc::NetworkInfoTag, sha_hash));
    P(offsetof(mc::NetworkInfoTag, appdata_size));
    P(sizeof(mc::EncryptedDataTag));
    P(sizeof(mc::BeaconDataCryptoCTR));
    P(offsetof(mc::BeaconDataCryptoCTR, wlan_comm_id));
    P(offsetof(mc::BeaconDataCryptoCTR, network_id));
    P(sizeof(mc::BeaconNodeInfo));
    P(offsetof(mc::BeaconNodeInfo, username));
    P(offsetof(mc::BeaconNodeInfo, network_node_id));
    P(sizeof(mc::BeaconData));
    P(offsetof(mc::BeaconData, bitmask));
    P(sizeof(mc::LLCHeader));
    P(offsetof(mc::LLCHeader, protocol));
    P(sizeof(mc::SecureDataHeader));
    P(offsetof(mc::SecureDataHeader, securedata_size));
    P(offsetof(mc::SecureDataHeader, dest_node_id));
    P(offsetof(mc::SecureDataHeader, src_node_id));
    P(sizeof(mc::DataFrameCryptoCTR));
    P(sizeof(mc::EAPoLNodeInfo));
    P(offsetof(mc::EAPoLNodeInfo, network_node_id));
    P(sizeof(mc::EAPoLStartPacket));
    P(offsetof(mc::EAPoLStartPacket, node));
    P(sizeof(mc::EAPoLLogoffPacket));
    P(offsetof(mc::EAPoLLogoffPacket, assigned_node_id));
    P(offsetof(mc::EAPoLLogoffPacket, client_mac_address));
    P(offsetof(mc::EAPoLLogoffPacket, connected_nodes));
    P(offsetof(mc::EAPoLLogoffPacket, nodes));
    P(sizeof(mc::AuthenticationFrame));
    P(sizeof(mc::AssociationResponseFrame));
    P(offsetof(mc::AssociationResponseFrame, assoc_id));
    P(sizeof(mc::GuestNodeInfo));
    P(offsetof(mc::GuestNodeInfo, username));
    P(offsetof(mc::GuestNodeInfo, network_node_id));
    P(sizeof(mc::GuestNetworkInfo));
    P(offsetof(mc::GuestNetworkInfo, oui_value));
    P(offsetof(mc::GuestNetworkInfo, wlan_comm_id));
    P(offsetof(mc::GuestNetworkInfo, network_id));
    P(offsetof(mc::GuestNetworkInfo, total_nodes));
    P(offsetof(mc::GuestNetworkInfo, max_nodes));
    P(offsetof(mc::GuestNetworkInfo, application_data_size));
    P(offsetof(mc::GuestNetworkInfo, application_data));
    P(sizeof(mc::ConnectionStatusMirror));
    P(offsetof(mc::ConnectionStatusMirror, network_node_id));
    P(offsetof(mc::ConnectionStatusMirror, nodes));
    P(offsetof(mc::ConnectionStatusMirror, total_nodes));
    P(offsetof(mc::ConnectionStatusMirror, node_bitmask));
    P(kGuestNodeInfoSize);
    P(kGuestNetworkInfoSize);
    P(kConnectionStatusSize);
    P(kEapolNodeInfoSize);
    P(kEapolStartPacketSize);
    P(kEapolLogoffPacketSize);
    P(kUdsMaxNodes);
    P(kApplicationDataSize);
    P(kEncryptedDataSizeCutoff);

    std::printf("-- yuzu (ldn) mirrors --\n");
    P(sizeof(my::SessionId));
    P(sizeof(my::IntentId));
    P(offsetof(my::IntentId, scene_id));
    P(sizeof(my::NetworkId));
    P(sizeof(my::Ssid));
    P(offsetof(my::Ssid, raw));
    P(sizeof(my::CommonNetworkInfo));
    P(offsetof(my::CommonNetworkInfo, ssid));
    P(offsetof(my::CommonNetworkInfo, channel));
    P(sizeof(my::NodeInfo));
    P(offsetof(my::NodeInfo, mac_address));
    P(offsetof(my::NodeInfo, node_id));
    P(offsetof(my::NodeInfo, is_connected));
    P(offsetof(my::NodeInfo, user_name));
    P(offsetof(my::NodeInfo, local_communication_version));
    P(sizeof(my::LdnNetworkInfo));
    P(offsetof(my::LdnNetworkInfo, node_count_max));
    P(offsetof(my::LdnNetworkInfo, node_count));
    P(offsetof(my::LdnNetworkInfo, nodes));
    P(offsetof(my::LdnNetworkInfo, advertise_data_size));
    P(offsetof(my::LdnNetworkInfo, advertise_data));
    P(offsetof(my::LdnNetworkInfo, random_authentication_id));
    P(sizeof(my::NetworkInfo));
    P(offsetof(my::NetworkInfo, common));
    P(offsetof(my::NetworkInfo, ldn));
    P(kLdnNodeInfoSize);
    P(kLdnNetworkInfoSize);
    P(kLdnNodeCountMax);
    P(kLdnAdvertiseDataSizeMax);
    P(kLdnAdvertiseDataSizeOffset);
    P(kLdnAdvertiseDataOffset);
    P(kLdnRandomAuthIdOffset);
    std::printf("-- six LDN body sizes --\n");
    P(ldn_body_size(LdnPacketType::Scan));
    P(ldn_body_size(LdnPacketType::ScanResp));
    P(ldn_body_size(LdnPacketType::Connect));
    P(ldn_body_size(LdnPacketType::SyncNetwork));
    P(ldn_body_size(LdnPacketType::Disconnect));
    P(ldn_body_size(LdnPacketType::DestroyNetwork));
    return 0;
}
