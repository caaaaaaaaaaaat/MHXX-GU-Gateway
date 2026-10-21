// SPDX-License-Identifier: GPL-3.0-or-later
// citra-control - Citra (UDS / 802.11) frame codec.
//
// Every field is converted with its own endianness; every parser consumes its
// input exactly (trailing bytes are an error) and every parser is safe under
// arbitrary prefix truncation because all reads go through the bounds-checked
// Reader and a failed read latches Err::Short.
#include "citra_control/uds_frames.hpp"

namespace citra_control {

// Layout cross-checks: the constants are one expression of the documented
// structures, so they are checked against each other at compile time.
static_assert(kGuestNodeInfoSize == 8 + 10 * 2 + 4 + 2 + 6, "guest NodeInfo layout");
static_assert(kEapolNodeInfoSize == kGuestNodeInfoSize, "wire and guest NodeInfo share a layout");
static_assert(kEapolStartPacketSize == 2 + 2 + 2 + 2 + kEapolNodeInfoSize, "EAPoLStartPacket layout");
static_assert(kEapolLogoffPacketSize == 2 + 2 + 2 + 6 + 6 + 1 + 1 + 4 + kUdsMaxNodes * kEapolNodeInfoSize,
              "EAPoLLogoffPacket layout");
static_assert(kGuestNetworkInfoSize == 6 + 1 + 1 + 1 + 3 + 3 + 1 + 4 + 1 + 1 + 2 + 4 + 1 + 1 + 2 + 0x1F + 1 + 0xC8,
              "guest NetworkInfo layout");
static_assert(kConnectionStatusSize == 4 + 4 + 2 + 2 + kUdsMaxNodes * 2 + 1 + 1 + 2, "ConnectionStatus layout");
static_assert(kBeaconNetworkInfoTagSize == kTagHeaderSize + 0x1F + 0x14 + 1, "NetworkInfoTag layout");
static_assert(kBeaconDataSize == 0x10 + 2, "BeaconData layout");
static_assert(kBeaconNodeInfoSize == 8 + 10 * 2 + 2, "BeaconNodeInfo layout");
static_assert(kBeaconNodeStride == kGuestNodeInfoSize, "encrypted beacon payload stride");
static_assert(kBeaconContentHeaderSize == kBeaconDataSize, "beacon content header alias");
static_assert(kAssocResponseTotalSize == kAssocResponseFrameSize + kAssocSsidTagSize, "AssociationResponse layout");
static_assert(kBeaconFrameHeaderSize == 8 + 2 + 2, "BeaconFrameHeader layout");
static_assert(kSecureDataHeaderSize == 2 + 2 + 2 + 1 + 1 + 2 + 2 + 2, "SecureDataHeader layout");

namespace {

// V-019: the beacon key is 16 zero bytes and the CTR is the raw
// BeaconDataCryptoCTR, used verbatim with no hash.
constexpr std::array<std::uint8_t, 16> kBeaconKey{};

void vendor_tag(Writer& w, std::uint8_t oui_type, const std::uint8_t* payload, std::size_t n) {
    w.u8(0xDD);
    w.u8(static_cast<std::uint8_t>(4 + n));
    w.bytes(kNintendoOui);
    w.u8(oui_type);
    w.bytes(payload, n);
}

// The 0x1F bytes of the guest NetworkInfo that the beacon's NetworkInfo tag
// carries (guest offsets 0xC..0x2A).
std::array<std::uint8_t, 0x1F> tag_network_info_bytes(const GuestNetworkInfo& n) {
    std::array<std::uint8_t, 0x1F> out{};
    out[0] = n.oui_value[0];
    out[1] = n.oui_value[1];
    out[2] = n.oui_value[2];
    out[3] = n.oui_type;
    store_u32be(out.data() + 4, n.wlan_comm_id);
    out[8] = n.id;
    store_u16be(out.data() + 10, n.attributes);
    store_u32be(out.data() + 12, n.network_id);
    out[16] = n.total_nodes;
    out[17] = n.max_nodes;
    for (std::size_t i = 0; i < 11; ++i) {
        out[20 + i] = n.reserved[i];
    }
    return out;
}

void apply_tag_network_info(const std::uint8_t* in, GuestNetworkInfo& n) {
    n.oui_value = {in[0], in[1], in[2]};
    n.oui_type = in[3];
    n.wlan_comm_id = load_u32be(in + 4);
    n.id = in[8];
    n.attributes = load_u16be(in + 10);
    n.network_id = load_u32be(in + 12);
    n.total_nodes = in[16];
    n.max_nodes = in[17];
    for (std::size_t i = 0; i < 11; ++i) {
        n.reserved[i] = in[20 + i];
    }
}

int upper_hex_value(std::uint8_t c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'A' && c <= 'F') {
        return 10 + (c - 'A');
    }
    return -1;
}

void build_note(Diag* diag, const char* where) {
    if (diag == nullptr) {
        return;
    }
    ++diag->c.frames_serialized;
    if (diag->events_enabled) {
        std::string s = "BUILD ";
        s += where;
        diag->log.push(std::move(s));
    }
}

void parse_note(Diag* diag, const char* where, std::uint64_t* counter) {
    if (counter != nullptr) {
        ++(*counter);
    }
    if (diag == nullptr) {
        return;
    }
    ++diag->c.frames_parsed;
    diag->note_ok(where, "parse");
}

bool valid_network_status(std::uint32_t v) {
    return v == 3 || v == 6 || v == 7 || v == 9 || v == 10;
}

bool valid_status_reason(std::uint32_t v) {
    return v == 0 || v == 1 || v == 4;
}

} // namespace

// ---------------------------------------------------------------------------
// LLC
// ---------------------------------------------------------------------------
void write_llc(Writer& w, EtherType protocol) {
    w.u8(0xAA); // SAP::SNAPExtensionUsed
    w.u8(0xAA);
    w.u8(0x03); // PDUControl::UnnumberedInformation
    w.zeros(3);
    w.u16be(static_cast<std::uint16_t>(protocol));
}

Res<LlcHeader> read_llc(Reader& r) {
    LlcHeader h;
    h.dsap = r.u8();
    h.ssap = r.u8();
    h.control = r.u8();
    r.copy_to(h.oui.data(), 3);
    const std::uint16_t protocol = r.u16be();
    if (!r.ok()) {
        return fail<LlcHeader>(r.err());
    }
    if (h.dsap != 0xAA || h.ssap != 0xAA || h.control != 0x03) {
        return fail<LlcHeader>(Err::BadTag);
    }
    if (h.oui[0] != 0 || h.oui[1] != 0 || h.oui[2] != 0) {
        return fail<LlcHeader>(Err::BadTag);
    }
    if (protocol == kEtherTypeSecureData) {
        h.protocol = EtherType::SecureData;
    } else if (protocol == kEtherTypeEapol) {
        h.protocol = EtherType::Eapol;
    } else {
        return fail<LlcHeader>(Err::BadEnum);
    }
    return ok(h);
}

Res<EtherType> llc_ether_type(const std::uint8_t* data, std::size_t size, Diag* diag) {
    Reader r(data, size);
    const Res<LlcHeader> h = read_llc(r);
    if (!h.ok()) {
        if (diag != nullptr) {
            diag->note_reject("llc_ether_type", h.err);
        }
        return fail<EtherType>(h.err);
    }
    return ok(h.value.protocol);
}

Res<std::uint16_t> eapol_frame_type(const std::uint8_t* data, std::size_t size, Diag* diag) {
    Reader r(data, size);
    const Res<LlcHeader> h = read_llc(r);
    if (!h.ok() || h.value.protocol != EtherType::Eapol) {
        const Err e = h.ok() ? Err::BadEnum : h.err;
        if (diag != nullptr) {
            diag->note_reject("eapol_frame_type", e);
        }
        return fail<std::uint16_t>(e);
    }
    const std::uint16_t magic = r.u16be();
    if (!r.ok()) {
        if (diag != nullptr) {
            diag->note_reject("eapol_frame_type", r.err());
        }
        return fail<std::uint16_t>(r.err());
    }
    return ok(magic);
}

// ---------------------------------------------------------------------------
// Guest structs
// ---------------------------------------------------------------------------
std::vector<std::uint8_t> serialize_guest_node_info(const GuestNodeInfo& v) {
    Writer w;
    w.u64le(v.friend_code_seed);
    for (std::size_t i = 0; i < 10; ++i) {
        w.u16le(v.username[i]);
    }
    w.zeros(4);
    w.u16le(v.network_node_id);
    w.zeros(6);
    return std::move(w.buf);
}

Res<GuestNodeInfo> parse_guest_node_info(const std::uint8_t* data, std::size_t size, Diag* diag) {
    auto rej = [&](Err e) {
        if (diag != nullptr) {
            diag->note_reject("guest_node_info", e);
        }
        return fail<GuestNodeInfo>(e);
    };
    if (size < kGuestNodeInfoSize) {
        return rej(Err::Short);
    }
    if (size > kGuestNodeInfoSize) {
        return rej(Err::Trailing);
    }
    Reader r(data, size);
    GuestNodeInfo v;
    v.friend_code_seed = r.u64le();
    for (std::size_t i = 0; i < 10; ++i) {
        v.username[i] = r.u16le();
    }
    r.skip(4);
    v.network_node_id = r.u16le();
    r.skip(6);
    if (!r.ok() || !r.at_end()) {
        return rej(r.ok() ? Err::Trailing : r.err());
    }
    parse_note(diag, "guest_node_info", diag == nullptr ? nullptr : &diag->c.uds_guest_nodeinfo_ok);
    return ok(v);
}

std::vector<std::uint8_t> serialize_guest_network_info(const GuestNetworkInfo& v) {
    Writer w;
    w.bytes(v.host_mac_address);
    w.u8(v.channel);
    w.u8(0);
    w.u8(v.initialized);
    w.zeros(3);
    w.bytes(v.oui_value);
    w.u8(v.oui_type);
    w.u32be(v.wlan_comm_id);
    w.u8(v.id);
    w.u8(0);
    w.u16be(v.attributes);
    w.u32be(v.network_id);
    w.u8(v.total_nodes);
    w.u8(v.max_nodes);
    w.zeros(2);
    w.bytes(v.reserved);
    w.u8(v.application_data_size);
    w.bytes(v.application_data);
    return std::move(w.buf);
}

Res<GuestNetworkInfo> parse_guest_network_info(const std::uint8_t* data, std::size_t size, Diag* diag) {
    auto rej = [&](Err e) {
        if (diag != nullptr) {
            diag->note_reject("guest_network_info", e);
        }
        return fail<GuestNetworkInfo>(e);
    };
    if (size < kGuestNetworkInfoSize) {
        return rej(Err::Short);
    }
    if (size > kGuestNetworkInfoSize) {
        return rej(Err::Trailing);
    }
    Reader r(data, size);
    GuestNetworkInfo v;
    r.copy_to(v.host_mac_address.data(), 6);
    v.channel = r.u8();
    r.skip(1);
    v.initialized = r.u8();
    r.skip(3);
    r.copy_to(v.oui_value.data(), 3);
    v.oui_type = r.u8();
    v.wlan_comm_id = r.u32be();
    v.id = r.u8();
    r.skip(1);
    v.attributes = r.u16be();
    v.network_id = r.u32be();
    v.total_nodes = r.u8();
    v.max_nodes = r.u8();
    r.skip(2);
    r.copy_to(v.reserved.data(), v.reserved.size());
    v.application_data_size = r.u8();
    r.copy_to(v.application_data.data(), v.application_data.size());
    if (!r.ok() || !r.at_end()) {
        return rej(r.ok() ? Err::Trailing : r.err());
    }
    if (v.oui_value != kNintendoOui) {
        return rej(Err::BadTag);
    }
    if (v.application_data_size > kApplicationDataSize) {
        return rej(Err::Oversize);
    }
    if (v.max_nodes > kUdsMaxNodes || v.total_nodes > kUdsMaxNodes) {
        return rej(Err::Range);
    }
    parse_note(diag, "guest_network_info", diag == nullptr ? nullptr : &diag->c.uds_guest_netinfo_ok);
    return ok(v);
}

std::vector<std::uint8_t> serialize_connection_status(const ConnectionStatus& v) {
    Writer w;
    w.u32le(static_cast<std::uint32_t>(v.status));
    w.u32le(static_cast<std::uint32_t>(v.status_change_reason));
    w.u16le(v.network_node_id);
    w.u16le(v.changed_nodes);
    for (std::size_t i = 0; i < kUdsMaxNodes; ++i) {
        w.u16le(v.nodes[i]);
    }
    w.u8(v.total_nodes);
    w.u8(v.max_nodes);
    w.u16le(v.node_bitmask);
    return std::move(w.buf);
}

Res<ConnectionStatus> parse_connection_status(const std::uint8_t* data, std::size_t size, Diag* diag) {
    auto rej = [&](Err e) {
        if (diag != nullptr) {
            diag->note_reject("connection_status", e);
        }
        return fail<ConnectionStatus>(e);
    };
    if (size < kConnectionStatusSize) {
        return rej(Err::Short);
    }
    if (size > kConnectionStatusSize) {
        return rej(Err::Trailing);
    }
    Reader r(data, size);
    ConnectionStatus v;
    const std::uint32_t status = r.u32le();
    const std::uint32_t reason = r.u32le();
    v.network_node_id = r.u16le();
    v.changed_nodes = r.u16le();
    for (std::size_t i = 0; i < kUdsMaxNodes; ++i) {
        v.nodes[i] = r.u16le();
    }
    v.total_nodes = r.u8();
    v.max_nodes = r.u8();
    v.node_bitmask = r.u16le();
    if (!r.ok() || !r.at_end()) {
        return rej(r.ok() ? Err::Trailing : r.err());
    }
    if (!valid_network_status(status) || !valid_status_reason(reason)) {
        return rej(Err::BadEnum);
    }
    if (v.max_nodes > kUdsMaxNodes || v.total_nodes > kUdsMaxNodes) {
        return rej(Err::Range);
    }
    v.status = static_cast<NetworkStatus>(status);
    v.status_change_reason = static_cast<NetworkStatusChangeReason>(reason);
    parse_note(diag, "connection_status", diag == nullptr ? nullptr : &diag->c.uds_connection_status_ok);
    return ok(v);
}

// ---------------------------------------------------------------------------
// Connection frames
// ---------------------------------------------------------------------------
Res<std::vector<std::uint8_t>> build_authentication_frame(const AuthenticationFrame& v, Diag* diag) {
    auto rej = [&](Err e) {
        if (diag != nullptr) {
            diag->note_reject("authentication_frame", e);
        }
        return fail<std::vector<std::uint8_t>>(e);
    };
    if (v.auth_algorithm != AuthAlgorithm::OpenSystem) {
        return rej(Err::BadEnum);
    }
    if (v.auth_seq != AuthenticationSeq::Seq1 && v.auth_seq != AuthenticationSeq::Seq2) {
        return rej(Err::BadEnum);
    }
    // A real Citra client path only ever expects the successful opening
    // handshake; anything else is refused instead of guessed (V-016k).
    if (v.status_code != AuthStatus::Successful) {
        return rej(Err::Unsafe);
    }
    Writer w;
    w.u16le(static_cast<std::uint16_t>(v.auth_algorithm));
    w.u16le(static_cast<std::uint16_t>(v.auth_seq));
    w.u16le(static_cast<std::uint16_t>(v.status_code));
    build_note(diag, "authentication_frame");
    return ok(std::move(w.buf));
}

Res<AuthenticationFrame> parse_authentication_frame(const std::uint8_t* data, std::size_t size, Diag* diag) {
    auto rej = [&](Err e) {
        if (diag != nullptr) {
            diag->note_reject("authentication_frame", e);
        }
        return fail<AuthenticationFrame>(e);
    };
    if (size < kAuthFrameSize) {
        return rej(Err::Short);
    }
    if (size > kAuthFrameSize) {
        return rej(Err::Trailing);
    }
    Reader r(data, size);
    AuthenticationFrame v;
    const std::uint16_t algorithm = r.u16le();
    const std::uint16_t seq = r.u16le();
    const std::uint16_t status = r.u16le();
    if (!r.ok() || !r.at_end()) {
        return rej(r.ok() ? Err::Trailing : r.err());
    }
    if (algorithm != static_cast<std::uint16_t>(AuthAlgorithm::OpenSystem)) {
        return rej(Err::BadEnum);
    }
    if (seq != static_cast<std::uint16_t>(AuthenticationSeq::Seq1) &&
        seq != static_cast<std::uint16_t>(AuthenticationSeq::Seq2)) {
        return rej(Err::BadEnum);
    }
    if (status != static_cast<std::uint16_t>(AuthStatus::Successful)) {
        return rej(Err::Unsafe);
    }
    v.auth_algorithm = AuthAlgorithm::OpenSystem;
    v.auth_seq = static_cast<AuthenticationSeq>(seq);
    v.status_code = AuthStatus::Successful;
    parse_note(diag, "authentication_frame", diag == nullptr ? nullptr : &diag->c.uds_auth_ok);
    return ok(v);
}

Res<std::vector<std::uint8_t>> build_association_response_frame(const AssociationResponse& v, Diag* diag) {
    auto rej = [&](Err e) {
        if (diag != nullptr) {
            if (e == Err::Unsafe) {
                ++diag->c.unsafe_assoc_blocked;
            }
            diag->note_reject("association_response", e);
        }
        return fail<std::vector<std::uint8_t>>(e);
    };
    // Citra ASSERT_MSG(std::get<AssocStatus>(assoc_result) ==
    // AssocStatus::Successful) has no NDEBUG guard, so a non-successful
    // AssociationResponse must never be generated (V-016k).
    if (v.status_code != AssocStatus::Successful) {
        return rej(Err::Unsafe);
    }
    if (v.association_id > 0x3FFF) {
        return rej(Err::Range);
    }
    Writer w;
    w.u16le(v.capabilities);
    w.u16le(static_cast<std::uint16_t>(v.status_code));
    w.u16le(static_cast<std::uint16_t>(v.association_id | kAssocIdMagic));
    w.u8(0);
    w.u8(8);
    const std::uint32_t id = v.network_id;
    for (int i = 7; i >= 0; --i) {
        w.u8(static_cast<std::uint8_t>("0123456789ABCDEF"[(id >> (4 * i)) & 0xFu]));
    }
    build_note(diag, "association_response");
    return ok(std::move(w.buf));
}

Res<AssociationResponse> parse_association_response_frame(const std::uint8_t* data, std::size_t size, Diag* diag) {
    auto rej = [&](Err e) {
        if (diag != nullptr) {
            if (e == Err::Unsafe) {
                ++diag->c.unsafe_assoc_blocked;
            }
            diag->note_reject("association_response", e);
        }
        return fail<AssociationResponse>(e);
    };
    if (size < kAssocResponseTotalSize) {
        return rej(Err::Short);
    }
    if (size > kAssocResponseTotalSize) {
        return rej(Err::Trailing);
    }
    Reader r(data, size);
    AssociationResponse v;
    v.capabilities = r.u16le();
    const std::uint16_t status = r.u16le();
    const std::uint16_t assoc_id = r.u16le();
    const std::uint8_t tag = r.u8();
    const std::uint8_t tag_len = r.u8();
    const std::uint8_t* text = r.raw(8);
    if (!r.ok() || !r.at_end() || text == nullptr) {
        return rej(r.ok() ? Err::Trailing : r.err());
    }
    if (tag != 0 || tag_len != 8) {
        return rej(Err::BadTag);
    }
    if (status != static_cast<std::uint16_t>(AssocStatus::Successful)) {
        return rej(Err::Unsafe);
    }
    std::uint32_t network_id = 0;
    for (std::size_t i = 0; i < 8; ++i) {
        const int hv = upper_hex_value(text[i]);
        if (hv < 0) {
            return rej(Err::Encoding);
        }
        network_id = (network_id << 4) | static_cast<std::uint32_t>(hv);
    }
    v.status_code = AssocStatus::Successful;
    v.association_id = static_cast<std::uint16_t>(assoc_id & 0x3FFFu);
    v.network_id = network_id;
    parse_note(diag, "association_response", diag == nullptr ? nullptr : &diag->c.uds_assoc_ok);
    return ok(v);
}

// ---------------------------------------------------------------------------
// EAPoL
// ---------------------------------------------------------------------------
void write_eapol_node_info(Writer& w, const EapolNodeInfo& v) {
    w.u64be(v.friend_code_seed);
    for (std::size_t i = 0; i < 10; ++i) {
        w.u16be(v.username[i]);
    }
    w.zeros(4);
    w.u16be(v.network_node_id);
    w.zeros(6);
}

Res<EapolNodeInfo> read_eapol_node_info(Reader& r) {
    EapolNodeInfo v;
    v.friend_code_seed = r.u64be();
    for (std::size_t i = 0; i < 10; ++i) {
        v.username[i] = r.u16be();
    }
    r.skip(4);
    v.network_node_id = r.u16be();
    r.skip(6);
    if (!r.ok()) {
        return fail<EapolNodeInfo>(r.err());
    }
    return ok(v);
}

Res<std::vector<std::uint8_t>> build_eapol_start_frame(const EapolStartPacket& v, Diag* diag) {
    Writer w;
    write_llc(w, EtherType::Eapol);
    w.u16be(kEapolStartMagic);
    w.u16be(v.association_id);
    w.u16be(kEapolUnknown);
    w.zeros(2);
    write_eapol_node_info(w, v.node);
    build_note(diag, "eapol_start");
    return ok(std::move(w.buf));
}

Res<EapolStartPacket> parse_eapol_start_frame(const std::uint8_t* data, std::size_t size, Diag* diag) {
    auto rej = [&](Err e) {
        if (diag != nullptr) {
            diag->note_reject("eapol_start", e);
        }
        return fail<EapolStartPacket>(e);
    };
    constexpr std::size_t kTotal = kLlcSize + kEapolStartPacketSize;
    if (size < kTotal) {
        return rej(Err::Short);
    }
    if (size > kTotal) {
        return rej(Err::Trailing);
    }
    Reader r(data, size);
    const Res<LlcHeader> llc = read_llc(r);
    if (!llc.ok()) {
        return rej(llc.err);
    }
    if (llc.value.protocol != EtherType::Eapol) {
        return rej(Err::BadEnum);
    }
    const std::uint16_t magic = r.u16be();
    EapolStartPacket v;
    v.association_id = r.u16be();
    const std::uint16_t unknown = r.u16be();
    r.skip(2);
    if (!r.ok()) {
        return rej(r.err());
    }
    if (magic != kEapolStartMagic) {
        return rej(Err::BadMagic);
    }
    if (unknown != kEapolUnknown) {
        return rej(Err::BadSentinel);
    }
    const Res<EapolNodeInfo> node = read_eapol_node_info(r);
    if (!node.ok()) {
        return rej(node.err);
    }
    if (!r.at_end()) {
        return rej(Err::Trailing);
    }
    v.node = node.value;
    parse_note(diag, "eapol_start", diag == nullptr ? nullptr : &diag->c.uds_eapol_start_ok);
    if (diag != nullptr) {
        ++diag->c.uds_eapol_nodeinfo_ok;
    }
    return ok(v);
}

Res<std::vector<std::uint8_t>> build_eapol_logoff_frame(const EapolLogoffPacket& v, Diag* diag) {
    auto rej = [&](Err e) {
        if (diag != nullptr) {
            diag->note_reject("eapol_logoff", e);
        }
        return fail<std::vector<std::uint8_t>>(e);
    };
    if (v.max_nodes > kUdsMaxNodes || v.connected_nodes > kUdsMaxNodes) {
        return rej(Err::Range);
    }
    Writer w;
    write_llc(w, EtherType::Eapol);
    w.u16be(kEapolLogoffMagic);
    w.zeros(2);
    w.u16be(v.assigned_node_id);
    w.bytes(v.client_mac_address);
    w.zeros(6);
    w.u8(v.connected_nodes);
    w.u8(v.max_nodes);
    w.zeros(4);
    for (std::size_t i = 0; i < kUdsMaxNodes; ++i) {
        write_eapol_node_info(w, v.nodes[i]);
    }
    build_note(diag, "eapol_logoff");
    return ok(std::move(w.buf));
}

Res<EapolLogoffPacket> parse_eapol_logoff_frame(const std::uint8_t* data, std::size_t size, Diag* diag) {
    auto rej = [&](Err e) {
        if (diag != nullptr) {
            diag->note_reject("eapol_logoff", e);
        }
        return fail<EapolLogoffPacket>(e);
    };
    constexpr std::size_t kTotal = kLlcSize + kEapolLogoffPacketSize;
    if (size < kTotal) {
        return rej(Err::Short);
    }
    if (size > kTotal) {
        return rej(Err::Trailing);
    }
    Reader r(data, size);
    const Res<LlcHeader> llc = read_llc(r);
    if (!llc.ok()) {
        return rej(llc.err);
    }
    if (llc.value.protocol != EtherType::Eapol) {
        return rej(Err::BadEnum);
    }
    const std::uint16_t magic = r.u16be();
    if (!r.ok()) {
        return rej(r.err());
    }
    if (magic != kEapolLogoffMagic) {
        return rej(Err::BadMagic);
    }
    EapolLogoffPacket v;
    r.skip(2);
    v.assigned_node_id = r.u16be();
    r.copy_to(v.client_mac_address.data(), 6);
    r.skip(6);
    v.connected_nodes = r.u8();
    v.max_nodes = r.u8();
    r.skip(4);
    for (std::size_t i = 0; i < kUdsMaxNodes; ++i) {
        const Res<EapolNodeInfo> node = read_eapol_node_info(r);
        if (!node.ok()) {
            return rej(node.err);
        }
        v.nodes[i] = node.value;
    }
    if (!r.ok() || !r.at_end()) {
        return rej(r.ok() ? Err::Trailing : r.err());
    }
    if (v.max_nodes > kUdsMaxNodes) {
        return rej(Err::Range);
    }
    if (v.connected_nodes > kUdsMaxNodes) {
        return rej(Err::Range);
    }
    parse_note(diag, "eapol_logoff", diag == nullptr ? nullptr : &diag->c.uds_eapol_logoff_ok);
    return ok(v);
}

// ---------------------------------------------------------------------------
// Secure data / node map / deauthentication
// ---------------------------------------------------------------------------
Res<std::vector<std::uint8_t>> build_secure_data_frame(const SecureDataFrame& v, Diag* diag) {
    auto rej = [&](Err e) {
        if (diag != nullptr) {
            diag->note_reject("secure_data", e);
        }
        return fail<std::vector<std::uint8_t>>(e);
    };
    const std::size_t n = v.payload.size();
    if (n > 0xFFFFu - kSecureDataHeaderSize) {
        return rej(Err::Oversize);
    }
    Writer w;
    write_llc(w, EtherType::SecureData);
    w.u16be(static_cast<std::uint16_t>(n + kSecureDataHeaderSize));
    w.zeros(2);
    w.u16be(static_cast<std::uint16_t>(n + 10));
    // is_management is always 0: Citra asserts on it (V-016k).
    w.u8(0);
    w.u8(v.header.data_channel);
    w.u16be(v.header.sequence_number);
    w.u16be(v.header.dest_node_id);
    w.u16be(v.header.src_node_id);
    w.bytes(v.payload.data(), n);
    build_note(diag, "secure_data");
    return ok(std::move(w.buf));
}

Res<SecureDataFrame> parse_secure_data_frame(const std::uint8_t* data, std::size_t size, Diag* diag) {
    auto rej = [&](Err e) {
        if (diag != nullptr) {
            if (e == Err::Unsafe) {
                ++diag->c.secure_data_management_rejected;
            }
            diag->note_reject("secure_data", e);
        }
        return fail<SecureDataFrame>(e);
    };
    constexpr std::size_t kMin = kLlcSize + kSecureDataHeaderSize;
    if (size < kMin) {
        return rej(Err::Short);
    }
    Reader r(data, size);
    const Res<LlcHeader> llc = read_llc(r);
    if (!llc.ok()) {
        return rej(llc.err);
    }
    if (llc.value.protocol != EtherType::SecureData) {
        return rej(Err::BadEnum);
    }
    SecureDataFrame v;
    const std::uint16_t protocol_size = r.u16be();
    r.skip(2);
    const std::uint16_t securedata_size = r.u16be();
    const std::uint8_t is_management = r.u8();
    v.header.data_channel = r.u8();
    v.header.sequence_number = r.u16be();
    v.header.dest_node_id = r.u16be();
    v.header.src_node_id = r.u16be();
    if (!r.ok()) {
        return rej(r.err());
    }
    if (is_management != 0) {
        return rej(Err::Unsafe);
    }
    if (protocol_size < kSecureDataHeaderSize || securedata_size < 10) {
        return rej(Err::BadLength);
    }
    const std::size_t expected = static_cast<std::size_t>(protocol_size) - kSecureDataHeaderSize;
    if (static_cast<std::size_t>(securedata_size) - 10 != expected) {
        return rej(Err::BadLength);
    }
    if (r.remaining() != expected) {
        return rej(r.ok() ? Err::BadLength : r.err());
    }
    v.payload = r.vec(expected);
    if (!r.ok() || !r.at_end()) {
        return rej(r.ok() ? Err::Trailing : r.err());
    }
    parse_note(diag, "secure_data", diag == nullptr ? nullptr : &diag->c.uds_secure_data_ok);
    return ok(v);
}

Res<std::vector<std::uint8_t>> build_node_map(const std::vector<NodeMapEntry>& entries, Diag* diag) {
    auto rej = [&](Err e) {
        if (diag != nullptr) {
            diag->note_reject("node_map", e);
        }
        return fail<std::vector<std::uint8_t>>(e);
    };
    if (entries.size() > kUdsMaxNodes) {
        return rej(Err::Range);
    }
    Writer w;
    // Citra memcpy's a host std::size_t (8 bytes on the gateway's x86_64 host).
    w.u64le(static_cast<std::uint64_t>(entries.size()));
    for (const NodeMapEntry& e : entries) {
        w.bytes(e.mac);
        w.u16le(e.node_id);
    }
    build_note(diag, "node_map");
    return ok(std::move(w.buf));
}

Res<std::vector<NodeMapEntry>> parse_node_map(const std::uint8_t* data, std::size_t size, Diag* diag) {
    auto rej = [&](Err e) {
        if (diag != nullptr) {
            diag->note_reject("node_map", e);
        }
        return fail<std::vector<NodeMapEntry>>(e);
    };
    if (size < 8) {
        return rej(Err::Short);
    }
    Reader r(data, size);
    const std::uint64_t count = r.u64le();
    if (!r.ok()) {
        return rej(r.err());
    }
    if (count > kUdsMaxNodes) {
        return rej(Err::Range);
    }
    const std::size_t expected = 8 + static_cast<std::size_t>(count) * 8;
    if (size != expected) {
        return rej(size < expected ? Err::Short : Err::Trailing);
    }
    std::vector<NodeMapEntry> out;
    out.reserve(static_cast<std::size_t>(count));
    for (std::uint64_t i = 0; i < count; ++i) {
        NodeMapEntry e;
        r.copy_to(e.mac.data(), 6);
        e.node_id = r.u16le();
        if (!r.ok()) {
            return rej(r.err());
        }
        out.push_back(e);
    }
    if (!r.at_end()) {
        return rej(Err::Trailing);
    }
    parse_note(diag, "node_map", diag == nullptr ? nullptr : &diag->c.uds_nodemap_ok);
    return ok(std::move(out));
}

// Deauthentication carries an empty payload in the Citra client
// (nwm_uds.cpp sets deauth.data = {}), so the body must be exactly 0 bytes.
Res<std::vector<std::uint8_t>> build_deauthentication_frame(Diag* diag) {
    build_note(diag, "deauthentication");
    return ok(std::vector<std::uint8_t>{});
}

Res<std::vector<std::uint8_t>> parse_deauthentication_frame(const std::uint8_t* data, std::size_t size, Diag* diag) {
    (void)data;
    if (size != 0) {
        if (diag != nullptr) {
            diag->note_reject("deauthentication", Err::Trailing);
        }
        return fail<std::vector<std::uint8_t>>(Err::Trailing);
    }
    parse_note(diag, "deauthentication", diag == nullptr ? nullptr : &diag->c.uds_deauth_ok);
    return ok(std::vector<std::uint8_t>{});
}

// ---------------------------------------------------------------------------
// Beacon
// ---------------------------------------------------------------------------
AesBlock make_beacon_ctr(const MacAddress& host_mac, std::uint32_t wlan_comm_id, std::uint8_t id,
                         std::uint32_t network_id) {
    AesBlock ctr{};
    for (std::size_t i = 0; i < 6; ++i) {
        ctr[i] = host_mac[i];
    }
    store_u32le(ctr.data() + 6, wlan_comm_id);
    ctr[10] = id;
    ctr[11] = 0;
    store_u32le(ctr.data() + 12, network_id);
    return ctr;
}

Res<std::vector<std::uint8_t>> build_beacon_frame(const BeaconParams& params, Diag* diag) {
    auto rej = [&](Err e) {
        if (diag != nullptr) {
            diag->note_reject("beacon", e);
        }
        return fail<std::vector<std::uint8_t>>(e);
    };
    if (params.nodes.size() > kUdsMaxNodes) {
        if (diag != nullptr) {
            ++diag->c.beacon_node_reject;
        }
        return rej(Err::Range);
    }
    const std::size_t node_count = params.nodes.size();
    // Citra's own boundary (spec R7): with fewer than 2 nodes the encrypted
    // payload 0x28n does not even cover the 0x12-byte BeaconData header plus its
    // bitmask.  Citra's generator then copies min(0xFA, 0x28n) bytes out of an
    // 0x12+0x1En buffer and its receiver (nwm_uds.cpp:1416-1419) reads 8 bytes
    // past the decrypted payload; that is inconsistent inside Citra itself, so
    // both the build and the parse path refuse it instead of emulating it.
    if (node_count < 2) {
        if (diag != nullptr) {
            ++diag->c.beacon_node_reject;
            diag->note_event("beacon", "beacon_max_nodes_too_small");
        }
        return rej(Err::BadLength);
    }
    // spec R6: Citra ASSERTs max_nodes == nodes.size() (uds_beacon.cpp:303), so a
    // caller-supplied max_nodes that disagrees is refused, never overridden.
    if (params.network_info.max_nodes != 0 && params.network_info.max_nodes != node_count) {
        if (diag != nullptr) {
            ++diag->c.beacon_node_reject;
        }
        return rej(Err::BadLength);
    }
    if (params.appdata_size > kApplicationDataSize) {
        return rej(Err::Oversize);
    }

    GuestNetworkInfo ni = params.network_info;
    // params.nodes.size() is max_nodes (record capacity): every record is
    // transmitted, while total_nodes may be smaller (only that many are
    // connected).  The receiver reads exactly max_nodes records.
    ni.max_nodes = static_cast<std::uint8_t>(node_count);
    ni.application_data_size = params.appdata_size;
    ni.application_data = params.appdata;

    const std::size_t content_size = kBeaconDataSize + node_count * kBeaconNodeInfoSize;
    // spec R5: the encrypted payload is 0x28 * n bytes (Citra NodeInfo stride);
    // [content_size, 0x28n) is the unverified tail and is zero-filled here.
    std::vector<std::uint8_t> plain(kBeaconNodeStride * node_count, 0);
    store_u16be(plain.data() + 0x10, params.bitmask);
    for (std::size_t i = 0; i < node_count; ++i) {
        std::uint8_t* p = plain.data() + kBeaconDataSize + i * kBeaconNodeInfoSize;
        store_u64be(p, params.nodes[i].friend_code_seed);
        for (std::size_t j = 0; j < 10; ++j) {
            store_u16be(p + 8 + j * 2, params.nodes[i].username[j]);
        }
        store_u16be(p + 0x1C, params.nodes[i].network_node_id);
    }
    // spec R3: MD5 covers plain[0x10, content_size) only (2 + 30n bytes).
    const Md5Digest digest = md5(plain.data() + 0x10, content_size - 0x10);
    for (std::size_t i = 0; i < digest.size(); ++i) {
        plain[i] = digest[i];
    }

    const AesBlock ctr = make_beacon_ctr(params.source_mac, ni.wlan_comm_id, ni.id, ni.network_id);
    Aes128 aes;
    aes.expand(kBeaconKey.data());
    const Err enc_err = aes128_ctr_xcrypt_stream(aes, ctr, plain.data(), plain.size(), diag);
    if (enc_err != Err::Ok) {
        return rej(enc_err);
    }

    const std::array<std::uint8_t, 0x1F> nib = tag_network_info_bytes(ni);
    Writer w;
    w.u64le(params.header.timestamp);
    w.u16le(params.header.beacon_interval);
    w.u16le(params.header.capabilities);
    // SSID tag: tag 0, length 8, all zero.
    w.u8(0);
    w.u8(8);
    w.zeros(8);
    // Dummy vendor tag.
    w.u8(0xDD);
    w.u8(7);
    w.bytes(kNintendoOui);
    w.u8(kNintendoTagIdDummy);
    w.bytes(kDummyTagData);
    // NetworkInfo vendor tag with its SHA-1 over the tag body (hash field zero).
    w.u8(0xDD);
    w.u8(static_cast<std::uint8_t>(52 + params.appdata_size));
    // nib already begins with Nintendo OUI and the NetworkInfo type.
    w.bytes(nib);
    {
        Writer hb;
        hb.bytes(nib);
        hb.zeros(0x14);
        hb.u8(params.appdata_size);
        hb.bytes(params.appdata.data(), params.appdata_size);
        const Sha1Digest digest = sha1(hb.buf.data(), hb.buf.size());
        w.bytes(digest);
    }
    w.u8(params.appdata_size);
    w.bytes(params.appdata.data(), params.appdata_size);
    // Encrypted payload, split at the 0xFA cutoff the receiver concatenates.
    const std::size_t cut = plain.size() < kEncryptedDataSizeCutoff ? plain.size() : kEncryptedDataSizeCutoff;
    vendor_tag(w, kNintendoTagIdEncryptedData0, plain.data(), cut);
    if (plain.size() > cut) {
        vendor_tag(w, kNintendoTagIdEncryptedData1, plain.data() + cut, plain.size() - cut);
    }
    build_note(diag, "beacon");
    return ok(std::move(w.buf));
}

Res<BeaconFrame> parse_beacon_frame(const std::uint8_t* data, std::size_t size, const MacAddress& source_mac,
                                    Diag* diag) {
    auto rej = [&](Err e) {
        if (diag != nullptr) {
            diag->note_reject("beacon", e);
        }
        return fail<BeaconFrame>(e);
    };
    Reader r(data, size);
    BeaconFrame out;
    out.header.timestamp = r.u64le();
    out.header.beacon_interval = r.u16le();
    out.header.capabilities = r.u16le();
    if (!r.ok()) {
        return rej(r.err());
    }
    // SSID tag.
    {
        const std::uint8_t tag = r.u8();
        const std::uint8_t len = r.u8();
        const std::uint8_t* ssid = r.raw(8);
        if (!r.ok() || ssid == nullptr) {
            return rej(r.ok() ? Err::Short : r.err());
        }
        if (tag != 0 || len != 8) {
            return rej(Err::BadTag);
        }
        for (std::size_t i = 0; i < 8; ++i) {
            if (ssid[i] != 0) {
                return rej(Err::BadSsid);
            }
        }
    }
    // Dummy vendor tag.
    {
        const std::uint8_t tag = r.u8();
        const std::uint8_t len = r.u8();
        std::array<std::uint8_t, 3> oui{};
        r.copy_to(oui.data(), 3);
        const std::uint8_t oui_type = r.u8();
        std::array<std::uint8_t, 3> body{};
        r.copy_to(body.data(), 3);
        if (!r.ok()) {
            return rej(r.err());
        }
        if (tag != 0xDD || len != 7 || oui != kNintendoOui || oui_type != kNintendoTagIdDummy ||
            body != kDummyTagData) {
            return rej(Err::BadTag);
        }
    }
    // NetworkInfo vendor tag.
    std::array<std::uint8_t, 0x1F> nib{};
    std::array<std::uint8_t, 0x14> sha_hash{};
    std::uint8_t appdata_size = 0;
    {
        const std::uint8_t tag = r.u8();
        const std::uint8_t len = r.u8();
        if (!r.ok()) {
            return rej(r.err());
        }
        if (tag != 0xDD) {
            return rej(Err::BadTag);
        }
        if (len < kBeaconNetworkInfoTagSize - kTagHeaderSize) {
            return rej(Err::BadLength);
        }
        r.copy_to(nib.data(), nib.size());
        if (!r.ok()) {
            return rej(r.err());
        }
        // Citra ASSERTs NintendoOUI + NintendoTagId::NetworkInfo here
        // (uds_beacon.cpp:134-135); we refuse instead of tripping that abort.
        if (nib[0] != kNintendoOui[0] || nib[1] != kNintendoOui[1] || nib[2] != kNintendoOui[2] ||
            nib[3] != kNintendoTagIdNetworkInfo) {
            return rej(Err::BadTag);
        }
        r.copy_to(sha_hash.data(), sha_hash.size());
        appdata_size = r.u8();
        if (!r.ok()) {
            return rej(r.err());
        }
        if (static_cast<std::size_t>(len) != (kBeaconNetworkInfoTagSize - kTagHeaderSize) + appdata_size) {
            return rej(Err::BadLength);
        }
        if (appdata_size > kApplicationDataSize) {
            return rej(Err::Oversize);
        }
        r.copy_to(out.appdata.data(), appdata_size);
        if (!r.ok()) {
            return rej(r.err());
        }
        Writer hb;
        hb.bytes(nib);
        hb.zeros(0x14);
        hb.u8(appdata_size);
        hb.bytes(out.appdata.data(), appdata_size);
        const Sha1Digest digest = sha1(hb.buf.data(), hb.buf.size());
        bool sha_match = true;
        for (std::size_t i = 0; i < sha_hash.size(); ++i) {
            if (sha_hash[i] != digest[i]) {
                sha_match = false;
            }
        }
        if (!sha_match) {
            if (diag != nullptr) {
                ++diag->c.sha1_verify_fail;
            }
            return rej(Err::BadDigest);
        }
    }
    // Encrypted data vendor tags (one or two, concatenated by the receiver).
    std::vector<std::uint8_t> enc;
    bool have0 = false;
    bool have1 = false;
    while (r.ok() && !r.at_end()) {
        const std::uint8_t tag = r.u8();
        const std::uint8_t len = r.u8();
        std::array<std::uint8_t, 3> oui{};
        r.copy_to(oui.data(), 3);
        const std::uint8_t oui_type = r.u8();
        if (!r.ok()) {
            return rej(r.err());
        }
        if (tag != 0xDD || oui != kNintendoOui) {
            return rej(Err::BadTag);
        }
        if (len < 4) {
            return rej(Err::BadLength);
        }
        const std::size_t payload_len = static_cast<std::size_t>(len) - 4;
        const std::uint8_t* payload = r.raw(payload_len);
        if (!r.ok() || payload == nullptr) {
            return rej(r.ok() ? Err::Short : r.err());
        }
        if (oui_type == kNintendoTagIdEncryptedData0) {
            if (have0 || have1) {
                return rej(Err::BadTag);
            }
            have0 = true;
        } else if (oui_type == kNintendoTagIdEncryptedData1) {
            if (!have0 || have1) {
                return rej(Err::BadTag);
            }
            have1 = true;
        } else {
            return rej(Err::BadEnum);
        }
        enc.insert(enc.end(), payload, payload + payload_len);
    }
    if (!r.ok()) {
        return rej(r.err());
    }
    if (!have0) {
        return rej(Err::BadTag);
    }
    GuestNetworkInfo ni{};
    apply_tag_network_info(nib.data(), ni);
    ni.application_data_size = appdata_size;
    ni.application_data = out.appdata;
    if (ni.max_nodes > kUdsMaxNodes) {
        if (diag != nullptr) {
            ++diag->c.beacon_node_reject;
        }
        return rej(Err::Range);
    }
    // spec R7: refuse Citra's sub-2-node inconsistency (see build_beacon_frame).
    if (ni.max_nodes < 2) {
        if (diag != nullptr) {
            ++diag->c.beacon_node_reject;
            diag->note_event("beacon", "beacon_max_nodes_too_small");
        }
        return rej(Err::BadLength);
    }
    const std::size_t content_size =
        kBeaconDataSize + static_cast<std::size_t>(ni.max_nodes) * kBeaconNodeInfoSize;
    // spec R1: the concatenated encrypted tags carry 0x28 * max_nodes bytes
    // (Citra NodeInfo stride), not 0x12 + 0x1E * max_nodes.
    const std::size_t expected = kBeaconNodeStride * static_cast<std::size_t>(ni.max_nodes);
    if (enc.size() != expected) {
        if (diag != nullptr) {
            ++diag->c.beacon_node_reject;
        }
        return rej(Err::BadLength);
    }
    const AesBlock ctr = make_beacon_ctr(source_mac, ni.wlan_comm_id, ni.id, ni.network_id);
    Aes128 aes;
    aes.expand(kBeaconKey.data());
    std::vector<std::uint8_t> plain = enc;
    const Err dec_err = aes128_ctr_xcrypt_stream(aes, ctr, plain.data(), plain.size(), diag);
    if (dec_err != Err::Ok) {
        return rej(dec_err);
    }
    const Md5Digest digest = md5(plain.data() + 0x10, content_size - 0x10);
    bool md5_match = true;
    for (std::size_t i = 0; i < digest.size(); ++i) {
        if (plain[i] != digest[i]) {
            md5_match = false;
        }
        out.md5_hash[i] = plain[i];
    }
    if (!md5_match) {
        if (diag != nullptr) {
            ++diag->c.md5_verify_fail;
        }
        return rej(Err::BadDigest);
    }
    out.bitmask = load_u16be(plain.data() + 0x10);
    out.nodes.reserve(ni.max_nodes);
    for (std::size_t i = 0; i < ni.max_nodes; ++i) {
        const std::uint8_t* p = plain.data() + kBeaconDataSize + i * kBeaconNodeInfoSize;
        BeaconNodeInfo node;
        node.friend_code_seed = load_u64be(p);
        for (std::size_t j = 0; j < 10; ++j) {
            node.username[j] = load_u16be(p + 8 + j * 2);
        }
        node.network_node_id = load_u16be(p + 0x1C);
        out.nodes.push_back(node);
    }
    out.sha_hash = sha_hash;
    out.appdata_size = appdata_size;
    out.network_info = ni;
    parse_note(diag, "beacon", diag == nullptr ? nullptr : &diag->c.uds_beacon_ok);
    return ok(out);
}

} // namespace citra_control
