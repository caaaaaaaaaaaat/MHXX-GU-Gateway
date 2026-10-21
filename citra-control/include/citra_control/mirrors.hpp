// SPDX-License-Identifier: GPL-3.0-or-later
// citra-control - compile-time mirrors of the Citra and yuzu on-disk/in-memory
// structures.  These mirrors exist ONLY so that sizeof/offsetof can be asserted
// at compile time (acceptance criterion 4).  The runtime code never casts a byte
// block to one of these; it converts field by field.
//
// Layouts follow:
//   citra-master/src/core/hle/service/nwm/{uds_beacon.h,uds_data.h,nwm_uds.h}
//   01052024-yuzu-mirror-master/src/core/hle/service/ldn/ldn_types.h
#pragma once

#include <cstddef>
#include <cstdint>

#pragma pack(push, 1)

namespace citra_control::mirror::citra {

// --- uds_beacon.h ---------------------------------------------------------
struct BeaconEntryHeader {          // 0x1C
    std::uint32_t total_size;       // 0x00
    std::uint8_t pad04[1];          // 0x04
    std::uint8_t wifi_channel;      // 0x05
    std::uint8_t pad06[2];          // 0x06
    std::uint8_t mac[6];            // 0x08
    std::uint8_t pad0e[6];          // 0x0E
    std::uint32_t unk_size;         // 0x14
    std::uint32_t header_size;      // 0x18
};
static_assert(sizeof(BeaconEntryHeader) == 0x1C, "BeaconEntryHeader must be 0x1C");
static_assert(offsetof(BeaconEntryHeader, mac) == 0x08, "BeaconEntryHeader.mac must be @8");
static_assert(offsetof(BeaconEntryHeader, unk_size) == 0x14, "BeaconEntryHeader.unk_size must be @0x14");

struct BeaconFrameHeader {          // 12
    std::uint64_t timestamp;        // 0x00 u64_le
    std::uint16_t beacon_interval;  // 0x08 u16_le
    std::uint16_t capabilities;     // 0x0A u16_le
};
static_assert(sizeof(BeaconFrameHeader) == 12, "BeaconFrameHeader must be 12");

struct TagHeader {              // 2
    std::uint8_t id;            // 0
    std::uint8_t length;        // 1
};
static_assert(sizeof(TagHeader) == 2, "TagHeader must be 2");

struct DummyTag {               // 9
    TagHeader header;           // 0: id 0xDD, length 7
    std::uint8_t oui[3];        // 2
    std::uint8_t oui_type;      // 5
    std::uint8_t data[3];       // 6
};
static_assert(sizeof(DummyTag) == 9, "DummyTag must be 9");
static_assert(offsetof(DummyTag, oui_type) == 5, "DummyTag.oui_type must be @5");

struct NetworkInfoTag {         // 54 + appdata
    TagHeader header;           // 0: id 0xDD, length 52 + appdata_size
    std::uint8_t network_info[0x1F];  // 2: guest NetworkInfo[0xC..0x2A]
    std::uint8_t sha_hash[0x14];      // 0x21
    std::uint8_t appdata_size;        // 0x35
    // std::uint8_t appdata[];        // 0x36
};
static_assert(sizeof(NetworkInfoTag) == 54, "NetworkInfoTag must be 54");
static_assert(offsetof(NetworkInfoTag, network_info) == 2, "NetworkInfoTag.network_info must be @2");
static_assert(offsetof(NetworkInfoTag, sha_hash) == 0x21, "NetworkInfoTag.sha_hash must be @0x21");
static_assert(offsetof(NetworkInfoTag, appdata_size) == 0x35, "NetworkInfoTag.appdata_size must be @0x35");

struct EncryptedDataTag {       // 6 + payload
    TagHeader header;           // 0: id 0xDD
    std::uint8_t oui[3];        // 2
    std::uint8_t oui_type;      // 5: 0x18 (EncryptedData0) or 0x19 (EncryptedData1)
};
static_assert(sizeof(EncryptedDataTag) == 6, "EncryptedDataTag must be 6");

struct BeaconDataCryptoCTR {    // 0x10, used verbatim as the AES-CTR counter
    std::uint8_t host_mac[6];   // 0x00
    std::uint32_t wlan_comm_id; // 0x06 u32_le
    std::uint8_t id;            // 0x0A
    std::uint8_t pad0b[1];      // 0x0B
    std::uint32_t network_id;   // 0x0C u32_le
};
static_assert(sizeof(BeaconDataCryptoCTR) == 0x10, "BeaconDataCryptoCTR must be 0x10");
static_assert(offsetof(BeaconDataCryptoCTR, wlan_comm_id) == 0x06, "ctr.wlan_comm_id must be @6");
static_assert(offsetof(BeaconDataCryptoCTR, network_id) == 0x0C, "ctr.network_id must be @0x0C");

struct BeaconNodeInfo {         // 0x1E
    std::uint64_t friend_code_seed;  // 0x00 u64_be
    std::uint16_t username[10];      // 0x08 10 x u16_be
    std::uint16_t network_node_id;   // 0x1C u16_be
};
static_assert(sizeof(BeaconNodeInfo) == 0x1E, "BeaconNodeInfo must be 0x1E");
static_assert(offsetof(BeaconNodeInfo, username) == 0x08, "BeaconNodeInfo.username must be @8");
static_assert(offsetof(BeaconNodeInfo, network_node_id) == 0x1C, "BeaconNodeInfo.network_node_id must be @0x1C");

struct BeaconData {             // 0x12
    std::uint8_t md5_hash[0x10];  // 0x00
    std::uint16_t bitmask;        // 0x10 u16_be
};
static_assert(sizeof(BeaconData) == 0x12, "BeaconData must be 0x12");
static_assert(offsetof(BeaconData, bitmask) == 0x10, "BeaconData.bitmask must be @0x10");

// --- uds_data.h -----------------------------------------------------------
struct LLCHeader {              // 8
    std::uint8_t dsap;          // 0
    std::uint8_t ssap;          // 1
    std::uint8_t control;       // 2
    std::uint8_t oui[3];        // 3
    std::uint16_t protocol;     // 6 enum_be<EtherType>
};
static_assert(sizeof(LLCHeader) == 8, "LLCHeader must be 8");
static_assert(offsetof(LLCHeader, protocol) == 6, "LLCHeader.protocol must be @6");

struct SecureDataHeader {             // 14
    std::uint16_t protocol_size;      // 0x00 u16_be
    std::uint8_t pad02[2];            // 0x02
    std::uint16_t securedata_size;    // 0x04 u16_be
    std::uint8_t is_management;       // 0x06
    std::uint8_t data_channel;        // 0x07
    std::uint16_t sequence_number;    // 0x08 u16_be
    std::uint16_t dest_node_id;       // 0x0A u16_be
    std::uint16_t src_node_id;        // 0x0C u16_be
};
static_assert(sizeof(SecureDataHeader) == 14, "SecureDataHeader must be 14");
static_assert(offsetof(SecureDataHeader, securedata_size) == 4, "SecureDataHeader.securedata_size must be @4");
static_assert(offsetof(SecureDataHeader, dest_node_id) == 0x0A, "SecureDataHeader.dest_node_id must be @0x0A");
static_assert(offsetof(SecureDataHeader, src_node_id) == 0x0C, "SecureDataHeader.src_node_id must be @0x0C");

struct DataFrameCryptoCTR {     // 16
    std::uint32_t wlan_comm_id;
    std::uint32_t network_id;
    std::uint8_t host_mac[6];
    std::uint16_t id;
};
static_assert(sizeof(DataFrameCryptoCTR) == 16, "DataFrameCryptoCTR must be 16");

struct EAPoLNodeInfo {          // 0x28
    std::uint64_t friend_code_seed;  // 0x00 u64_be
    std::uint16_t username[10];      // 0x08 10 x u16_be
    std::uint8_t pad1c[4];           // 0x1C
    std::uint16_t network_node_id;   // 0x20 u16_be
    std::uint8_t pad22[6];           // 0x22
};
static_assert(sizeof(EAPoLNodeInfo) == 0x28, "EAPoLNodeInfo must be 0x28");
static_assert(offsetof(EAPoLNodeInfo, network_node_id) == 0x20, "EAPoLNodeInfo.network_node_id must be @0x20");

struct EAPoLStartPacket {            // 0x30
    std::uint16_t magic;             // 0x00 u16_be = 0x201
    std::uint16_t association_id;    // 0x02 u16_be
    std::uint16_t unknown;           // 0x04 u16_be = 1
    std::uint8_t pad06[2];           // 0x06
    EAPoLNodeInfo node;              // 0x08
};
static_assert(sizeof(EAPoLStartPacket) == 0x30, "EAPoLStartPacket must be 0x30");
static_assert(offsetof(EAPoLStartPacket, node) == 0x08, "EAPoLStartPacket.node must be @8");

struct EAPoLLogoffPacket {           // 0x298
    std::uint16_t magic;             // 0x00 u16_be = 0x202
    std::uint8_t pad02[2];           // 0x02
    std::uint16_t assigned_node_id;  // 0x04 u16_be
    std::uint8_t client_mac_address[6];  // 0x06
    std::uint8_t pad0c[6];           // 0x0C
    std::uint8_t connected_nodes;    // 0x12
    std::uint8_t max_nodes;          // 0x13
    std::uint8_t pad14[4];           // 0x14
    EAPoLNodeInfo nodes[16];         // 0x18
};
static_assert(sizeof(EAPoLLogoffPacket) == 0x298, "EAPoLLogoffPacket must be 0x298");
static_assert(offsetof(EAPoLLogoffPacket, assigned_node_id) == 4, "EAPoLLogoffPacket.assigned_node_id must be @4");
static_assert(offsetof(EAPoLLogoffPacket, client_mac_address) == 6, "EAPoLLogoffPacket.client_mac must be @6");
static_assert(offsetof(EAPoLLogoffPacket, connected_nodes) == 0x12, "EAPoLLogoffPacket.connected_nodes must be @0x12");
static_assert(offsetof(EAPoLLogoffPacket, nodes) == 0x18, "EAPoLLogoffPacket.nodes must be @0x18");

// --- uds_connection.h -----------------------------------------------------
struct AuthenticationFrame {    // 6
    std::uint16_t auth_algorithm;  // 0 enum_le
    std::uint16_t auth_seq;        // 2 enum_le
    std::uint16_t status_code;     // 4 enum_le
};
static_assert(sizeof(AuthenticationFrame) == 6, "AuthenticationFrame must be 6");

struct AssociationResponseFrame {  // 6
    std::uint16_t capabilities;    // 0
    std::uint16_t status_code;     // 2 enum_le
    std::uint16_t assoc_id;        // 4
};
static_assert(sizeof(AssociationResponseFrame) == 6, "AssociationResponseFrame must be 6");
static_assert(offsetof(AssociationResponseFrame, assoc_id) == 4, "AssociationResponseFrame.assoc_id must be @4");

// --- nwm_uds.h ------------------------------------------------------------
struct GuestNodeInfo {          // 40
    std::uint64_t friend_code_seed;  // 0x00 u64_le
    std::uint16_t username[10];      // 0x08 10 x u16_le
    std::uint8_t pad1c[4];           // 0x1C
    std::uint16_t network_node_id;   // 0x20 u16_le
    std::uint8_t pad22[6];           // 0x22
};
static_assert(sizeof(GuestNodeInfo) == 40, "guest NodeInfo must be 40");
static_assert(offsetof(GuestNodeInfo, username) == 8, "guest NodeInfo.username must be @8");
static_assert(offsetof(GuestNodeInfo, network_node_id) == 0x20, "guest NodeInfo.network_node_id must be @0x20");

struct GuestNetworkInfo {              // 0x108
    std::uint8_t host_mac_address[6];  // 0x00
    std::uint8_t channel;              // 0x06
    std::uint8_t pad07[1];             // 0x07
    std::uint8_t initialized;          // 0x08
    std::uint8_t pad09[3];             // 0x09
    std::uint8_t oui_value[3];         // 0x0C
    std::uint8_t oui_type;             // 0x0F
    std::uint32_t wlan_comm_id;        // 0x10 u32_be
    std::uint8_t id;                   // 0x14
    std::uint8_t pad15[1];             // 0x15
    std::uint16_t attributes;          // 0x16 u16_be
    std::uint32_t network_id;          // 0x18 u32_be
    std::uint8_t total_nodes;          // 0x1C
    std::uint8_t max_nodes;            // 0x1D
    std::uint8_t pad1e[2];             // 0x1E
    std::uint8_t reserved20[0x1F];     // 0x20
    std::uint8_t application_data_size;  // 0x3F
    std::uint8_t application_data[0xC8]; // 0x40
};
static_assert(sizeof(GuestNetworkInfo) == 0x108, "guest NetworkInfo must be 0x108");
static_assert(offsetof(GuestNetworkInfo, oui_value) == 0xC, "guest NetworkInfo.oui_value must be @0xC");
static_assert(offsetof(GuestNetworkInfo, wlan_comm_id) == 0x10, "guest NetworkInfo.wlan_comm_id must be @0x10");
static_assert(offsetof(GuestNetworkInfo, network_id) == 0x18, "guest NetworkInfo.network_id must be @0x18");
static_assert(offsetof(GuestNetworkInfo, total_nodes) == 0x1C, "guest NetworkInfo.total_nodes must be @0x1C");
static_assert(offsetof(GuestNetworkInfo, max_nodes) == 0x1D, "guest NetworkInfo.max_nodes must be @0x1D");
static_assert(offsetof(GuestNetworkInfo, application_data_size) == 0x3F, "guest NetworkInfo.appdata_size must be @0x3F");
static_assert(offsetof(GuestNetworkInfo, application_data) == 0x40, "guest NetworkInfo.appdata must be @0x40");

struct ConnectionStatusMirror {   // 0x30
    std::uint32_t status;           // 0x00 enum_le
    std::uint32_t status_change_reason;  // 0x04 enum_le
    std::uint16_t network_node_id;  // 0x08
    std::uint16_t changed_nodes;    // 0x0A
    std::uint16_t nodes[16];        // 0x0C
    std::uint8_t total_nodes;       // 0x2C
    std::uint8_t max_nodes;         // 0x2D
    std::uint16_t node_bitmask;     // 0x2E
};
static_assert(sizeof(ConnectionStatusMirror) == 0x30, "ConnectionStatus must be 0x30");
static_assert(offsetof(ConnectionStatusMirror, network_node_id) == 8, "ConnectionStatus.network_node_id must be @8");
static_assert(offsetof(ConnectionStatusMirror, nodes) == 0xC, "ConnectionStatus.nodes must be @0xC");
static_assert(offsetof(ConnectionStatusMirror, total_nodes) == 0x2C, "ConnectionStatus.total_nodes must be @0x2C");
static_assert(offsetof(ConnectionStatusMirror, node_bitmask) == 0x2E, "ConnectionStatus.node_bitmask must be @0x2E");

} // namespace citra_control::mirror::citra

namespace citra_control::mirror::yuzu {

struct SessionId {              // 0x10
    std::uint64_t high;
    std::uint64_t low;
};
static_assert(sizeof(SessionId) == 0x10, "SessionId must be 0x10");

struct IntentId {               // 0x10
    std::uint64_t local_communication_id;  // 0x00
    std::uint8_t reserved08[2];            // 0x08
    std::uint16_t scene_id;                // 0x0A
    std::uint8_t reserved0c[4];            // 0x0C
};
static_assert(sizeof(IntentId) == 0x10, "IntentId must be 0x10");
static_assert(offsetof(IntentId, scene_id) == 0x0A, "IntentId.scene_id must be @0x0A");

struct NetworkId {              // 0x20
    IntentId intent_id;
    SessionId session_id;
};
static_assert(sizeof(NetworkId) == 0x20, "NetworkId must be 0x20");

struct Ssid {                   // 0x22
    std::uint8_t length;
    char raw[33];
};
static_assert(sizeof(Ssid) == 0x22, "Ssid must be 0x22");
static_assert(offsetof(Ssid, raw) == 1, "Ssid.raw must be @1");

struct CommonNetworkInfo {      // 0x30
    std::uint8_t bssid[6];      // 0x00
    Ssid ssid;                  // 0x06
    std::int16_t channel;       // 0x28
    std::int8_t link_level;     // 0x2A
    std::uint8_t network_type;  // 0x2B
    std::uint8_t pad2c[4];      // 0x2C
};
static_assert(sizeof(CommonNetworkInfo) == 0x30, "CommonNetworkInfo must be 0x30");
static_assert(offsetof(CommonNetworkInfo, ssid) == 6, "CommonNetworkInfo.ssid must be @6");
static_assert(offsetof(CommonNetworkInfo, channel) == 0x28, "CommonNetworkInfo.channel must be @0x28");

struct NodeInfo {                     // 0x40
    std::uint8_t ipv4_address[4];     // 0x00
    std::uint8_t mac_address[6];      // 0x04
    std::int8_t node_id;              // 0x0A
    std::uint8_t is_connected;        // 0x0B
    std::uint8_t user_name[33];       // 0x0C
    std::uint8_t reserved2d[1];       // 0x2D
    std::int16_t local_communication_version;  // 0x2E
    std::uint8_t reserved30[0x10];    // 0x30
};
static_assert(sizeof(NodeInfo) == 0x40, "NodeInfo must be 0x40");
static_assert(offsetof(NodeInfo, mac_address) == 4, "NodeInfo.mac_address must be @4");
static_assert(offsetof(NodeInfo, node_id) == 0x0A, "NodeInfo.node_id must be @0x0A");
static_assert(offsetof(NodeInfo, is_connected) == 0x0B, "NodeInfo.is_connected must be @0x0B");
static_assert(offsetof(NodeInfo, user_name) == 0x0C, "NodeInfo.user_name must be @0x0C");
static_assert(offsetof(NodeInfo, local_communication_version) == 0x2E, "NodeInfo.version must be @0x2E");

struct LdnNetworkInfo {               // 0x430
    std::uint8_t security_parameter[0x10];  // 0x000
    std::uint16_t security_mode;            // 0x010
    std::uint8_t station_accept_policy;     // 0x012
    std::uint8_t has_action_frame;          // 0x013
    std::uint8_t pad014[2];                 // 0x014
    std::uint8_t node_count_max;            // 0x016
    std::uint8_t node_count;                // 0x017
    NodeInfo nodes[8];                      // 0x018 (NodeCountMax == 8)
    std::uint8_t pad218[2];                 // 0x218
    std::uint16_t advertise_data_size;      // 0x21A
    std::uint8_t advertise_data[0x180];     // 0x21C
    std::uint8_t reserved39c[0x8C];         // 0x39C
    std::uint64_t random_authentication_id; // 0x428
};
static_assert(sizeof(LdnNetworkInfo) == 0x430, "LdnNetworkInfo must be 0x430");
static_assert(offsetof(LdnNetworkInfo, node_count_max) == 0x16, "node_count_max must be @0x16");
static_assert(offsetof(LdnNetworkInfo, node_count) == 0x17, "node_count must be @0x17");
static_assert(offsetof(LdnNetworkInfo, nodes) == 0x18, "nodes must be @0x18");
static_assert(offsetof(LdnNetworkInfo, advertise_data_size) == 0x21A, "advertise_data_size must be @0x21A");
static_assert(offsetof(LdnNetworkInfo, advertise_data) == 0x21C, "advertise_data must be @0x21C");
static_assert(offsetof(LdnNetworkInfo, random_authentication_id) == 0x428, "random_authentication_id must be @0x428");

struct NetworkInfo {            // 0x480
    NetworkId network_id;       // 0x000
    CommonNetworkInfo common;   // 0x020
    LdnNetworkInfo ldn;         // 0x050
};
static_assert(sizeof(NetworkInfo) == 0x480, "NetworkInfo must be 0x480");
static_assert(offsetof(NetworkInfo, common) == 0x20, "NetworkInfo.common must be @0x20");
static_assert(offsetof(NetworkInfo, ldn) == 0x50, "NetworkInfo.ldn must be @0x50");

} // namespace citra_control::mirror::yuzu

#pragma pack(pop)
