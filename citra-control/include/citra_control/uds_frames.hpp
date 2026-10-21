// SPDX-License-Identifier: GPL-3.0-or-later
// citra-control - Citra side frames: 802.11/UDS management and EAPoL frames.
//
// Endianness is per field: the on-wire Citra frames mix big-endian (EAPoL and
// beacon tag payloads) and little-endian (guest structs, connection frames).
// Every field is converted explicitly; no block is ever cast to a struct.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "citra_control/bytes.hpp"
#include "citra_control/crypto.hpp"

namespace citra_control {

// ---------------------------------------------------------------------------
// Sizes and constants (citra-master/src/core/hle/service/nwm/).
// ---------------------------------------------------------------------------
inline constexpr std::size_t kLlcSize = 8;
inline constexpr std::size_t kBeaconFrameHeaderSize = 12;
inline constexpr std::size_t kTagHeaderSize = 2;
inline constexpr std::size_t kBeaconNetworkInfoTagSize = 54; // 2 + 0x1F + 0x14 + 1
inline constexpr std::size_t kBeaconDummyTagSize = 9;
inline constexpr std::size_t kBeaconDataSize = 0x12;
inline constexpr std::size_t kBeaconNodeInfoSize = 0x1E;
// Citra's per-node wire stride on the encrypted (Nintendo) payload: the
// concatenation of both encrypted tags is exactly kBeaconNodeStride * max_nodes
// bytes, while only the first kBeaconDataSize + kBeaconNodeInfoSize * max_nodes
// are meaningful (see docs/G4-BEACON-LENGTH-FIX-SPEC.md).  kBeaconNodeStride is
// sizeof(nwm::NodeInfo) (src/core/hle/service/nwm/nwm_uds.h), i.e. the same
// 0x28-byte layout the receiver copies node records out of.
inline constexpr std::size_t kBeaconNodeStride = 0x28;
// Alias for kBeaconDataSize used when the "meaningful content" length is
// contrasted with the full encrypted payload; kept as a separate named constant
// so the two lengths are never confused.
inline constexpr std::size_t kBeaconContentHeaderSize = 0x12;
inline constexpr std::size_t kBeaconSsidTagSize = 10; // 2 + 8
inline constexpr std::size_t kEncryptedDataSizeCutoff = 0xFA;
inline constexpr std::size_t kUdsMaxNodes = 16;
inline constexpr std::size_t kApplicationDataSize = 0xC8;
inline constexpr std::size_t kGuestNodeInfoSize = 40;
inline constexpr std::size_t kGuestNetworkInfoSize = 0x108;
inline constexpr std::size_t kConnectionStatusSize = 0x30;
inline constexpr std::size_t kEapolNodeInfoSize = 0x28;
inline constexpr std::size_t kEapolStartPacketSize = 0x30;
inline constexpr std::size_t kEapolLogoffPacketSize = 0x298;
inline constexpr std::size_t kSecureDataHeaderSize = 14;
inline constexpr std::size_t kAuthFrameSize = 6;
inline constexpr std::size_t kAssocResponseFrameSize = 6;
inline constexpr std::size_t kAssocSsidTagSize = 10;
inline constexpr std::size_t kAssocResponseTotalSize = 16;

inline constexpr std::uint16_t kEapolStartMagic = 0x201;
inline constexpr std::uint16_t kEapolLogoffMagic = 0x202;
inline constexpr std::uint16_t kEapolUnknown = 1;
inline constexpr std::uint16_t kAssocIdMagic = 0xC000;
inline constexpr std::uint16_t kBroadcastNetworkNodeId = 0xFFFF;
inline constexpr std::uint64_t kDefaultNetworkUptime = 900000000ull;
inline constexpr std::uint16_t kDefaultBeaconInterval = 100;
inline constexpr std::uint16_t kDefaultExtraCapabilities = 0x0431;

inline constexpr std::uint8_t kNintendoTagIdDummy = 20;
inline constexpr std::uint8_t kNintendoTagIdNetworkInfo = 21;
inline constexpr std::uint8_t kNintendoTagIdEncryptedData0 = 24;
inline constexpr std::uint8_t kNintendoTagIdEncryptedData1 = 25;
inline constexpr std::array<std::uint8_t, 3> kNintendoOui = {0x00, 0x1F, 0x32};
inline constexpr std::array<std::uint8_t, 3> kDummyTagData = {0x0A, 0x00, 0x00};

inline constexpr std::uint16_t kEtherTypeSecureData = 0x876D;
inline constexpr std::uint16_t kEtherTypeEapol = 0x888E;

inline constexpr MacAddress kBroadcastMac = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

// ---------------------------------------------------------------------------
// Enums.
// ---------------------------------------------------------------------------
enum class EtherType : std::uint16_t {
    SecureData = kEtherTypeSecureData,
    Eapol = kEtherTypeEapol,
};

enum class AuthenticationSeq : std::uint16_t { Seq1 = 1, Seq2 = 2 };
enum class AuthAlgorithm : std::uint16_t { OpenSystem = 0 };
enum class AuthStatus : std::uint16_t { Successful = 0 };
enum class AssocStatus : std::uint16_t { Successful = 0 };

enum class NetworkStatus : std::uint32_t {
    NotConnected = 3,
    ConnectedAsHost = 6,
    Connecting = 7,
    ConnectedAsClient = 9,
    ConnectedAsSpectator = 10,
};

enum class NetworkStatusChangeReason : std::uint32_t {
    None = 0,
    ConnectionEstablished = 1,
    ConnectionLost = 4,
};

// ---------------------------------------------------------------------------
// Structs.
// ---------------------------------------------------------------------------
struct LlcHeader {
    std::uint8_t dsap = 0xAA;      // SAP::SNAPExtensionUsed
    std::uint8_t ssap = 0xAA;
    std::uint8_t control = 0x03;   // PDUControl::UnnumberedInformation
    std::array<std::uint8_t, 3> oui = {0, 0, 0};
    EtherType protocol = EtherType::Eapol;
};

struct BeaconFrameHeader {
    std::uint64_t timestamp = kDefaultNetworkUptime;   // u64_le
    std::uint16_t beacon_interval = kDefaultBeaconInterval; // u16_le
    std::uint16_t capabilities = kDefaultExtraCapabilities; // u16_le
};

// Guest (nwm_uds.h) NodeInfo, 40 bytes, little-endian.
struct GuestNodeInfo {
    std::uint64_t friend_code_seed = 0;  // u64_le
    Username username{};                 // 10 x u16_le
    std::uint16_t network_node_id = 0;   // u16_le
};

// Guest (nwm_uds.h) NetworkInfo, 0x108 bytes.  u32_be/u16_be fields are the
// game's big-endian values; the (de)serializer converts field by field.
struct GuestNetworkInfo {
    MacAddress host_mac_address{};
    std::uint8_t channel = 0;
    std::uint8_t initialized = 0;
    std::array<std::uint8_t, 3> oui_value = kNintendoOui;
    std::uint8_t oui_type = kNintendoTagIdNetworkInfo;
    std::uint32_t wlan_comm_id = 0;   // u32_be
    std::uint8_t id = 0;
    std::uint16_t attributes = 0;     // u16_be
    std::uint32_t network_id = 0;     // u32_be
    std::uint8_t total_nodes = 0;
    std::uint8_t max_nodes = 0;
    std::array<std::uint8_t, 0x1F> reserved{};
    std::uint8_t application_data_size = 0;
    std::array<std::uint8_t, kApplicationDataSize> application_data{};
};

struct ConnectionStatus {
    NetworkStatus status = NetworkStatus::NotConnected;
    NetworkStatusChangeReason status_change_reason = NetworkStatusChangeReason::None;
    std::uint16_t network_node_id = 0;
    std::uint16_t changed_nodes = 0;
    std::array<std::uint16_t, kUdsMaxNodes> nodes{};
    std::uint8_t total_nodes = 0;
    std::uint8_t max_nodes = 0;
    std::uint16_t node_bitmask = 0;
};

struct AuthenticationFrame {
    AuthAlgorithm auth_algorithm = AuthAlgorithm::OpenSystem;
    AuthenticationSeq auth_seq = AuthenticationSeq::Seq1;
    AuthStatus status_code = AuthStatus::Successful;
};

// AssociationResponseFrame(6) followed by an 8-byte uppercase-hex SSID tag.
struct AssociationResponse {
    std::uint16_t capabilities = kDefaultExtraCapabilities;
    AssocStatus status_code = AssocStatus::Successful;
    std::uint16_t association_id = 0;
    std::uint32_t network_id = 0;
};

// EAPoLNodeInfo, 0x28, big-endian.
struct EapolNodeInfo {
    std::uint64_t friend_code_seed = 0;  // u64_be
    Username username{};                 // 10 x u16_be
    std::uint16_t network_node_id = 0;   // u16_be
};

struct EapolStartPacket {
    std::uint16_t association_id = 0;  // u16_be
    EapolNodeInfo node{};
};

struct EapolLogoffPacket {
    std::uint16_t assigned_node_id = 0;  // u16_be
    MacAddress client_mac_address{};
    std::uint8_t connected_nodes = 0;
    std::uint8_t max_nodes = 0;
    std::array<EapolNodeInfo, kUdsMaxNodes> nodes{};
};

struct SecureDataHeader {
    std::uint8_t data_channel = 0;
    std::uint16_t sequence_number = 0;  // u16_be
    std::uint16_t dest_node_id = 0;     // u16_be
    std::uint16_t src_node_id = 0;      // u16_be
    // protocol_size / securedata_size are derived from the payload length and
    // is_management is always 0 (V-016k: Citra ASSERTs on is_management != 0).
};

struct SecureDataFrame {
    SecureDataHeader header{};
    std::vector<std::uint8_t> payload;
};

struct NodeMapEntry {
    MacAddress mac{};
    std::uint16_t node_id = 0;
};

// Beacon plaintext node record (uds_beacon.h BeaconNodeInfo, 0x1E).
struct BeaconNodeInfo {
    std::uint64_t friend_code_seed = 0;  // u64_be
    Username username{};                 // 10 x u16_be
    std::uint16_t network_node_id = 0;   // u16_be
};

struct BeaconParams {
    BeaconFrameHeader header{};
    GuestNetworkInfo network_info{};
    std::uint8_t appdata_size = 0;
    std::array<std::uint8_t, kApplicationDataSize> appdata{};
    std::vector<BeaconNodeInfo> nodes;
    std::uint16_t bitmask = 0;
    // Transmitter MAC.  It is also the CTR host_mac, so it must stay stable for
    // the whole session and differ between hosts (V-016k rule 8).
    MacAddress source_mac{};
};

struct BeaconFrame {
    BeaconFrameHeader header{};
    GuestNetworkInfo network_info{};  // bytes 0xC..0x2A are restored; the rest are zero
    std::array<std::uint8_t, 0x14> sha_hash{};
    std::uint8_t appdata_size = 0;
    std::array<std::uint8_t, kApplicationDataSize> appdata{};
    std::array<std::uint8_t, 0x10> md5_hash{};
    std::uint16_t bitmask = 0;
    std::vector<BeaconNodeInfo> nodes;
};

// ---------------------------------------------------------------------------
// LLC / EtherType helpers.
// ---------------------------------------------------------------------------
void write_llc(Writer& w, EtherType protocol);
Res<LlcHeader> read_llc(Reader& r);
Res<EtherType> llc_ether_type(const std::uint8_t* data, std::size_t size, Diag* diag);
Res<std::uint16_t> eapol_frame_type(const std::uint8_t* data, std::size_t size, Diag* diag);

// ---------------------------------------------------------------------------
// Guest structs.
// ---------------------------------------------------------------------------
std::vector<std::uint8_t> serialize_guest_node_info(const GuestNodeInfo& v);
Res<GuestNodeInfo> parse_guest_node_info(const std::uint8_t* data, std::size_t size, Diag* diag = nullptr);
std::vector<std::uint8_t> serialize_guest_network_info(const GuestNetworkInfo& v);
Res<GuestNetworkInfo> parse_guest_network_info(const std::uint8_t* data, std::size_t size, Diag* diag = nullptr);

std::vector<std::uint8_t> serialize_connection_status(const ConnectionStatus& v);
Res<ConnectionStatus> parse_connection_status(const std::uint8_t* data, std::size_t size, Diag* diag = nullptr);

// ---------------------------------------------------------------------------
// Connection frames.
// ---------------------------------------------------------------------------
Res<std::vector<std::uint8_t>> build_authentication_frame(const AuthenticationFrame& v, Diag* diag = nullptr);
Res<AuthenticationFrame> parse_authentication_frame(const std::uint8_t* data, std::size_t size, Diag* diag = nullptr);
Res<std::vector<std::uint8_t>> build_association_response_frame(const AssociationResponse& v, Diag* diag = nullptr);
Res<AssociationResponse> parse_association_response_frame(const std::uint8_t* data, std::size_t size,
                                                          Diag* diag = nullptr);

// ---------------------------------------------------------------------------
// EAPoL frames (LLC header included in the returned/consumed buffer).
// ---------------------------------------------------------------------------
void write_eapol_node_info(Writer& w, const EapolNodeInfo& v);
Res<EapolNodeInfo> read_eapol_node_info(Reader& r);
Res<std::vector<std::uint8_t>> build_eapol_start_frame(const EapolStartPacket& v, Diag* diag = nullptr);
Res<EapolStartPacket> parse_eapol_start_frame(const std::uint8_t* data, std::size_t size, Diag* diag = nullptr);
Res<std::vector<std::uint8_t>> build_eapol_logoff_frame(const EapolLogoffPacket& v, Diag* diag = nullptr);
Res<EapolLogoffPacket> parse_eapol_logoff_frame(const std::uint8_t* data, std::size_t size, Diag* diag = nullptr);

// ---------------------------------------------------------------------------
// Data / node map / deauthentication.
// ---------------------------------------------------------------------------
Res<std::vector<std::uint8_t>> build_secure_data_frame(const SecureDataFrame& v, Diag* diag = nullptr);
Res<SecureDataFrame> parse_secure_data_frame(const std::uint8_t* data, std::size_t size, Diag* diag = nullptr);
Res<std::vector<std::uint8_t>> build_node_map(const std::vector<NodeMapEntry>& entries, Diag* diag = nullptr);
Res<std::vector<NodeMapEntry>> parse_node_map(const std::uint8_t* data, std::size_t size, Diag* diag = nullptr);
Res<std::vector<std::uint8_t>> build_deauthentication_frame(Diag* diag = nullptr);
Res<std::vector<std::uint8_t>> parse_deauthentication_frame(const std::uint8_t* data, std::size_t size,
                                                            Diag* diag = nullptr);

// ---------------------------------------------------------------------------
// Beacon.
// ---------------------------------------------------------------------------
// CTR = raw BeaconDataCryptoCTR bytes (host_mac 6 + wlan_comm_id u32_le + id +
// pad + network_id u32_le).  It is used verbatim, with no hash (V-019).
AesBlock make_beacon_ctr(const MacAddress& host_mac, std::uint32_t wlan_comm_id, std::uint8_t id,
                         std::uint32_t network_id);
Res<std::vector<std::uint8_t>> build_beacon_frame(const BeaconParams& params, Diag* diag = nullptr);
Res<BeaconFrame> parse_beacon_frame(const std::uint8_t* data, std::size_t size, const MacAddress& source_mac,
                                    Diag* diag = nullptr);

} // namespace citra_control
