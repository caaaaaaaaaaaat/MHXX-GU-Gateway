// SPDX-License-Identifier: GPL-2.0-or-later
// G-b' control-plane bridge (M4).  One ControlBridge per joined Citra session.
//
// The bridge owns exactly one citra_control::ControlPlane plus a Diag.  It
// never touches sockets, clocks, files or the wire: every method takes already
// decoded inputs and returns ControlEmission values that the gateway either
// queues on the Citra TCP connection or sends over the frozen room transport.
// All LDN / UDS bytes come from citra-control encoders; the gateway never
// hand-writes a control-plane frame on the wire.
//
// Declared constants (nothing here is copied from a capture; see
// docs/citra-gateway-report.md section 13 "G-b' control-plane bridge"):
//   * channel 6 (accepts Wifi24_6), link level Excellent, network type Ldn
//   * Citra/UDS beacon emission every 100 ms -- the rate the Beacon frame
//     itself advertizes -- node_count_max 8 (kLdnNodeCountMax)
//   * association_id 1 (| kAssocIdMagic), local_communication_version 1
//   * bssid / seed = FNV-1a of "<room name>:<room port>", then
//     02 00 <h24> <h16> <h8> <h0> as the transmitter MAC
#pragma once

#include "citra_gateway/identity.hpp"

#include "citra_control/bytes.hpp"
#include "citra_control/ldn_ctrl.hpp"
#include "citra_control/map.hpp"
#include "citra_control/state.hpp"
#include "citra_control/uds_frames.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace citra_gateway {

// UDS beacon cadence.  The Beacon frame advertizes its own interval
// (citra_control::kDefaultBeaconInterval = 100 ms, see uds_frames.hpp), and a
// real MHXX host beacons every ~100 ms; the gateway used to *declare* 100 ms and
// emit every 200 ms.  gc7 (2026-10-15) showed that costs the synthetic host the
// second beacon a joining client needs: the client cancels the association
// ~285 ms after it connects, and the first beacon that lists the guest only left
// the gateway at +182 ms, i.e. the next one was due at +383 ms.  Nothing else
// uses this value -- control.cpp is the only rate limit -- and the LDN side of
// the bridge never emits a periodic beacon of its own.
inline constexpr std::uint16_t kControlBeaconIntervalMs = 100;
inline constexpr std::int16_t kControlChannel = 6;
inline constexpr std::size_t kControlMaxStations = 7;      // kLdnStationCountMax
// V-245: rolling heartbeat observation window (per-session kinds, so the window
// must be large enough to span the whole hall lifetime at ~1 frame/s per side).
inline constexpr std::size_t kHeartbeatWindowMax = 4096;
// G1/D2 (docs/G4-GATEWAY-BEACON-FIX-SPEC.md): the advertised Beacon record
// capacity -- the Beacon's max_nodes -- NOT the number of connected nodes.
// Citra rejects any beacon whose record count differs from max_nodes (R6),
// and MHXX renders a one-in-four room, so the gateway advertises a 4 slot room
// that grows with the session.  One shared constant, defined here next to the
// other kControl* values, so control.cpp and the acceptance harness agree.
inline constexpr std::size_t kControlBeaconCapacity = 4;
inline constexpr std::uint16_t kControlAssociationId = 1;
inline constexpr std::uint8_t kControlLinkLevel = 3;       // LinkLevel::Excellent
inline constexpr std::uint8_t kControlNetworkType = 2;     // PackedNetworkType::Ldn
inline constexpr std::int16_t kControlVersion = 1;
inline constexpr std::uint8_t kControlBeaconId = 0;
inline constexpr std::uint8_t kControlInitialized = 1;
inline constexpr const char* kControlFallbackSsid = "CITRAGWB";

// D3/N1 (docs/G4-UDS-NODE-ID-FIX-SPEC.md section 1): the UDS node id table.
// UDS ids are a different numbering from the LDN node ids above (LDN host = 0,
// station slots 1..kControlMaxStations), and the two are never mixed.  This
// bridge owns the UDS host id 1; the Citra peer is the room's first guest and
// always takes node 2, whatever id it declares in its own EAPoL-Start (real
// Citra clients send an uninitialised 0 -- spec section 0.1).  An LDN station
// in slot k lands on UDS id k + 2; the "+ 2" lives only in this one function.
inline constexpr std::uint16_t kControlHostNodeId = 1;
inline constexpr std::uint16_t kControlCitraPeerNodeId = 2;

inline constexpr std::uint16_t station_uds_node_id(std::int8_t ldn_node_id) {
    return static_cast<std::uint16_t>(ldn_node_id) + kControlCitraPeerNodeId;
}

// V-266: reverse UDS association injection timing.  The gateway has to present
// each admitted Yuzu station to Citra as a *joining UDS guest* before MHXX will
// greet it, and Citra's association sequence has no timer of its own (a real
// client just resends).  The bridge bounds the whole Idle -> AwaitAssocResp ->
// AwaitLogoff -> Done sequence with this value: on expiry the station's state
// returns to Idle and guest_inject_timeout is counted, so a half-finished
// injection is always visible in counters instead of hanging silently.
inline constexpr std::uint64_t kControlGuestInjectTimeoutMs = 1500;

// V-268: the friend_code_seed the bridge declares for every injected guest.  A
// real 3DS/Citra client leaves the field at zero unless the game set one, and
// the bridge has no captured per-station seed, so it declares zero and MHXX
// derives the guest's identity word from that (see identity.hpp:
// mhxx_identity_word_from_seed -> 0x6522df69, the word V-267 measured in the
// member table's second slot).  Named here so the frame builder and the
// translation path can never disagree about which seed was declared.
inline constexpr std::uint64_t kGuestDeclaredSeed = 0;

// V-268: member-table slot count bound for the 0x0111 endpoint table.  The
// measured frame carries 8 nine-byte slots and a real MHXX hall holds at most
// kUdsMaxNodes players; the bound only has to reject a byte that is not a
// count, never to model the game's true capacity.
inline constexpr std::size_t kMemberTableMaxCount = 16;

// V-267: how long the Citra peer's beacon application data stays usable as the
// LDN advertise_data.  A real MHXX host beacons every ~100 ms (the Beacon frame
// advertizes that interval itself, kDefaultBeaconInterval), so this window is 15
// consecutive missed beacons -- far longer than the gap between two beacons of a
// live hall, and the same order of magnitude as the only other liveness bound in
// this bridge (kControlGuestInjectTimeoutMs, also 1500 ms).  Past it the LDN side
// stops advertising the peer's hall and falls back to --ldn-advertise-hex
// (advertise_citra_expired), because a hall name that outlives its beacon is a
// hall name that may describe a hall which no longer exists.
inline constexpr std::uint64_t kCitraAppdataMaxAgeMs = 1500;

// V-266: per station injection state machine.  Idle is both "never armed" and
// "gave up" -- the counter tells the two apart (guest_inject_timeout).  Done
// means Citra answered the EAPoL-Start with its logoff, i.e. it assigned the
// station an id in its own node_map.
enum class GuestInjectionState : std::uint8_t {
    Idle = 0,
    AwaitAssocResp = 1,
    AwaitLogoff = 2,
    Done = 3,
};

// Deterministic 32-bit FNV-1a.  Documented so the report and the harness can
// re-derive the room seed without sharing code with this file.
std::uint32_t control_fnv1a32(const std::string& text);

// Reverse-host discovery: convert the measured 200-byte MHGU hall layout to
// MHXX appdata. Transport discovery/admission is handled separately.
std::optional<citra_room::Bytes> convert_gu_hall_advertise(const citra_room::Bytes& gu);

struct ControlOptions {
    std::string room_name;
    std::uint32_t room_seed = 0;
    std::uint16_t beacon_interval_ms = kControlBeaconIntervalMs;
    std::int16_t channel = kControlChannel;
    std::uint16_t scene_id = 0;

    // V-111 (docs/G4-UDS-BEACON-PROFILE-SPEC.md): opt-in UDS beacon identity
    // profile.  A real MHXX host advertises constant identity fields in the
    // Beacon's NetworkInfo tag -- wlan_comm_id, id, attributes, network_id and a
    // two byte word straight after max_nodes -- plus 200 bytes of application
    // data, and it is MHXX (not Citra, whose receiver filters only by
    // transmitter MAC, nwm_uds.cpp:57-72) that decides which beacon is a hall it
    // may list.  Every field is opt-in: with all have_ flags false the encoder
    // output is byte for byte what it was before these options existed, so the
    // G3/D2/D3 acceptance bytes are unaffected.
    std::uint32_t uds_wlan_comm_id = 0;
    bool have_uds_wlan_comm_id = false;
    // V-239: cross-game LDN identity override (see gateway.hpp Options for the
    // measured motivation).  0 keeps the derived mix32 identity.
    std::uint64_t ldn_comm_id_override = 0;
    std::uint64_t ldn_session_id = 0;
    // V-239: game advertise data carried in ScanResp/SyncNetwork.  MHGU only
    // lists a hall whose NetworkInfo advertises its private 200-byte structure
    // (measured in g2-run2: real AP ad_size=200, gateway ad_size=0 was never
    // listed).  Empty keeps size 0.
    std::vector<std::uint8_t> ldn_advertise_data;
    // V-267: advertise the Citra peer's *live* Beacon application data instead of
    // the static --ldn-advertise-hex template whenever one has been received.
    // Default true, because the user-visible goal of the bridge is the MHXX hall
    // name in the Yuzu list; false keeps the pre-V-267 behaviour byte for byte
    // (only ldn_advertise_data is ever advertised, and a received appdata is
    // recorded but never adopted -- advertise_live_disabled).
    bool ldn_live_advertise = true;
    // Suppress discovery/admission unless a fresh Citra hall beacon exists.
    bool ldn_require_live_hall = false;
    // GU-host discovery role: station scans and fresh converted GU beacons.
    // Association/game admission is deliberately a separate implementation.
    bool ldn_gu_host_discovery = false;
    bool ldn_gu_host_admission = false;
    // V-259: cross-game data-plane first integration.  When enabled, kind-0
    // session-announce packets observed in Citra UDS Data frames get their
    // 4-byte identity words substituted (XX word -> GU word per pair) and are
    // emitted to the Yuzu members as Proxy packets.  Disabled by default; the
    // V-232 gate review precedes any default-on.
    bool ldn_announce_forward = false;
    // V-266: reverse UDS association injection.  With this gate on, every Yuzu
    // station admitted through LdnType::Connect is additionally presented to
    // Citra as a joining UDS guest, because Citra's nwm_uds only answers game
    // traffic for MACs in its node_map: MHXX sees "nobody joined the hall" and
    // produces no Pia bytes at all until the map has a second entry.
    //
    // Sequence (citra-master/src/core/hle/service/nwm/nwm_uds.cpp):
    //   1. gateway sends Authentication SEQ1 with source = the station's MAC and
    //      destination = this bridge's bssid; Citra answers SEQ2 plus an
    //      AssociationResponse (HandleAuthenticationFrame :427-463 -- accepted
    //      only while status == ConnectedAsHost, MAC absent from node_map, room
    //      not full).
    //   2. on a successful AssociationResponse the gateway sends EAPoL-Start
    //      (HandleEAPoLPacket :192-320 assigns the node id, updates node_info and
    //      broadcasts an EAPoL-Logoff).
    //   3. the gateway reads the assigned node id out of that Logoff and stores
    //      it on the station.
    //
    // Armed only when the Citra peer has actually beaconed (a packet of type
    // Beacon can only originate from a Citra that is hosting -- see
    // BeaconBroadcastCallback :1439-1445); an announce counter is never the
    // criterion.  Off by default: with the gate off no byte, state or counter of
    // the historical paths changes.
    bool ldn_guest_inject = false;
    // V-275: the bidirectional experimental path also maps the header sender.
    // Real V-274 36-byte responses contain no body address at all.
    bool ldn_game_return = false;
    struct LdnIdentityPair {
        std::array<std::uint8_t, 4> xx_word{};
        std::array<std::uint8_t, 4> gu_word{};
    };
    std::vector<LdnIdentityPair> ldn_identity_pairs;
    std::uint8_t uds_beacon_id = 0;
    bool have_uds_beacon_id = false;
    std::uint16_t uds_attributes = 0;
    bool have_uds_attributes = false;
    std::uint32_t uds_network_id = 0;
    bool have_uds_network_id = false;
    // Wire NetworkInfo[0x1E..0x1F]: the two bytes the frozen encoder writes as
    // zeros after max_nodes and that no BeaconParams field reaches.  The gateway
    // patches them into the finished frame and recomputes the tag SHA-1.
    std::uint16_t uds_tag_word = 0;
    bool have_uds_tag_word = false;
    // Beacon application data (wire appdata_size + appdata, at most
    // kApplicationDataSize bytes).  have_uds_appdata false keeps size 0.
    std::vector<std::uint8_t> uds_appdata;
    bool have_uds_appdata = false;
    // V-111/D4: the identity of the synthetic host record (UDS node 1).  A real
    // MHXX host advertises a friend-code seed and a username on node 1 (spec
    // section 2.5); this bridge used to write a present-but-anonymous record.
    std::uint64_t uds_host_seed = 0;
    bool have_uds_host_seed = false;
    citra_control::Username uds_host_username{};
    bool have_uds_host_username = false;
};

struct ControlStation {
    // The ipv4_address field exactly as the station declared it in its LDN
    // Connect node_info, kept byte for byte. `fake_ip` is the room side address
    // used for routing; the declared field is what goes back into a synthesized
    // NetworkInfo when it is present (never invented, never transformed).
    std::array<std::uint8_t, 4> declared_ipv4{};
    bool have_declared_ipv4 = false;
    citra_room::MacAddress mac{};
    room_client::IPv4 fake_ip{};
    std::int8_t node_id = 0;
    citra_control::UserNameBytes user_name{};
    citra_control::Username uds_username{};
    std::int16_t local_communication_version = kControlVersion;

    // V-266: state of the reverse UDS association injection (see
    // ControlOptions::ldn_guest_inject).  Idle for every station while the gate
    // is off, so every pre-V-266 station is byte for byte the old station.
    GuestInjectionState guest_inject_state = GuestInjectionState::Idle;
    // Bridge clock when the current wait started (diagnostic; the timeout is
    // computed from it in tick()).
    std::uint64_t guest_inject_armed_ms = 0;
    // Association id Citra granted in its AssociationResponse; echoed in the
    // EAPoL-Start exactly as Citra's own client does (masked, i.e. 1).
    std::uint16_t guest_inject_assoc_id = 0;
    // The node id Citra assigned this station in *Citra's* numbering, taken from
    // its EAPoL-Logoff.  This is NOT station_uds_node_id()'s gateway numbering:
    // the two are recorded side by side and never mixed (Citra's own
    // GetNextAvailableNodeId decides this one).  Citra's Logoff generator never
    // writes client_mac_address, so the field arrives as six zero bytes and the
    // bridge attributes such a Logoff to the oldest waiting station by order
    // (guest_inject_logoff_ordered); a non-zero MAC that matches no waiting
    // station assigns nothing (guest_inject_logoff_unmatched).
    bool have_uds_node_id = false;
    std::uint16_t uds_node_id = 0;

    // V-268: the identity word MHXX derives for this station from the seed the
    // bridge declares in its EAPoL-Start (kGuestDeclaredSeed).  Citra assigns
    // the station a node in its own node_map, MHXX turns that node's NodeInfo
    // seed into a 4-byte endpoint word, and the member table therefore carries
    // *this* word where the Yuzu side expects the station's own fake IP.  The
    // value is a function of the declared seed only (not of the MAC), and is
    // identical for every injected station, which is why the slot-position rule
    // in translate_mh_packet is the one that must not fail.
    std::array<std::uint8_t, 4> guest_identity_word{};
    std::uint64_t guest_seed = kGuestDeclaredSeed;
    bool have_guest_identity_word = false;
};

// One outbound control-plane frame.  to_citra selects which side of the
// gateway serialises and sends it.
struct ControlEmission {
    bool to_citra = false;
    std::string kind;
    // Citra side (802.11 / EAPoL payload placed in WifiPacket.data).
    citra_room::FrameType citra_type = citra_room::FrameType::Data;
    bool citra_broadcast = false;
    citra_room::Bytes citra_data;
    // V-266: address override for the injected association frames.  Every other
    // emission leaves with the gateway's own identity (transmitter = bssid,
    // destination = the Citra peer), but an injected Authentication / EAPoL
    // frame has to look like it came from the Yuzu station: Citra keys node_map
    // on the frame's transmitter address (nwm_uds.cpp
    // HandleAuthenticationFrame:440) and answers to it.  Set only by the
    // injection path; the gateway resolves both fields verbatim.
    bool have_citra_addresses = false;
    citra_room::MacAddress citra_transmitter{};
    citra_room::MacAddress citra_destination{};
    // Room side (LDN body placed in LdnPacket.data).
    room_client::LdnType ldn_type = room_client::LdnType::Scan;
    room_client::IPv4 ldn_remote_ip{};
    bool ldn_broadcast = false;
    room_client::Bytes ldn_body;
    // V-259: Room side ProxyPacket carrier (translated game announce for the
    // cross-game data plane).  The bytes are the MH packet (32AB9864 header at
    // offset 0), sent as a room ProxyPacket to the Yuzu members.
    bool room_proxy = false;
    room_client::IPv4 proxy_remote_ip{};
    bool proxy_broadcast = false;
    room_client::Bytes proxy_data;
};

// V-261: one bounded observation of an inbound Citra Data frame.  A real run
// cannot be replayed under a debugger, and the announce forward depends on a
// stack of measured preconditions (magic offset, route, identity word, station
// table), so the bridge records why each candidate did or did not forward.
// Diagnostic only: no behaviour reads it.
struct DataFrameSample {
    std::string verdict;   // gate-off | no-magic | prereq | route | no-word | forwarded
    std::size_t bytes = 0; // Citra-side payload length
    int base = -1;         // 0 or 41 when the 32AB9864 magic matched, else -1
    std::string head_hex;  // first 48 payload bytes, lowercase hex
};

// Gateway-provided identity mapping for one inbound LDN packet.
struct LdnContext {
    citra_room::MacAddress mapped_mac{};
    bool have_mapped_mac = false;
};

struct LdnHandling {
    std::vector<ControlEmission> emissions;
    bool accepted = false;   // the bridge's own plane changed state
    room_client::LdnType type = room_client::LdnType::Scan;
};

// Identity proved by this gateway's own authenticated guest session.
struct GuHostGuestIdentity {
    room_client::IPv4 host_ip{}, guest_ip{};
    std::uint64_t session_high = 0, session_low = 0;
    citra_room::MacAddress mac{};
    citra_control::EapolNodeInfo node{};
    bool have_descriptor = false;
    std::array<std::uint8_t, 70> descriptor{};
};

// A local Citra guest identified by its own EAPoL Start and the real host's
// addressed Logoff. The assigned node id is never taken from its Start.
struct CitraHostPeerIdentity {
    citra_room::MacAddress mac{};
    room_client::IPv4 ip{};
    citra_control::EapolNodeInfo node{};
    std::uint16_t assigned_node_id = 0;
};

class ControlBridge {
public:
    ControlBridge(const ControlOptions& options, const room_client::IPv4& session_fake_ip,
                  const citra_room::MacAddress& session_mac);
    ~ControlBridge();
    ControlBridge(const ControlBridge&) = delete;
    ControlBridge& operator=(const ControlBridge&) = delete;

    // AP lifetime (ap_initialized -> ap_opened -> ap_created) plus the first
    // beacon.  Called once per session, after the room information is known.
    std::vector<ControlEmission> start();
    // Periodic beacon, rate limited to options().beacon_interval_ms.
    std::vector<ControlEmission> tick(std::uint64_t now_ms);
    // Release a reverse-host membership before its room transport is stopped.
    std::vector<ControlEmission> on_transport_departure();

    // Citra side inbound management frames (Beacon/Auth/AssocResp/Deauth/NodeMap).
    std::vector<ControlEmission> on_citra_wifi(const citra_room::WifiPacket& wifi, std::uint64_t now_ms);
    // V-267: the Citra peer's beacon application data -- the 200 byte structure
    // MHXX puts into its UDS Beacon, whose hall name sits at offset 52 as UTF-16LE
    // (24 code units).  on_citra_wifi calls this for every inbound
    // Beacon, so a caller only needs the entry point when it already decoded the
    // frame itself.  Adopted only when 0 < size <= kLdnAdvertiseDataSizeMax and
    // the live gate is on (ControlOptions::ldn_live_advertise); every other case
    // is counted and leaves the previously stored value untouched.  Recorded with
    // the source MAC and the bridge clock (kCitraAppdataMaxAgeMs retires it).
    void on_citra_beacon_appdata(const citra_room::Bytes& appdata,
                                 const citra_room::MacAddress& source_mac, std::uint64_t now_ms);
    // Citra side inbound LLC EtherType EAPoL frame (Start 0x201 / Logoff 0x202).
    std::vector<ControlEmission> on_citra_eapol(const citra_room::Bytes& frame, std::uint64_t now_ms);
    // Direct mixed-platform peer traffic within this Citra-hosted hall. Uses
    // independent per-pair codec state and never changes the host/GU admission.
    std::vector<ControlEmission> on_citra_host_peer_game(
        const citra_room::WifiPacket& wifi, const CitraHostPeerIdentity& local,
        std::uint64_t now_ms);
    std::vector<ControlEmission> on_citra_host_peer_proxy(
        const room_client::IPv4& source, const citra_room::Bytes& plain,
        const CitraHostPeerIdentity& local, std::uint64_t now_ms);
    // Owner calls after authenticating Start identity against host Logoff.
    std::vector<ControlEmission> register_citra_host_peer(const CitraHostPeerIdentity& local);
    std::vector<ControlEmission> forget_citra_host_peer(const citra_room::MacAddress& mac);
    // Citra side inbound secure data frame: true => the gateway may forward it
    // opaquely (control plane is Connected), false => rejected and counted.
    bool on_citra_secure_data();
    // V-263: a 32AB9864 game frame that arrived from the Citra side while it is
    // the UDS *host* (measured: MHXX creates the hall, SecureData src_node_id
    // 1).  The bridge never associates as that host's guest, so this frame does
    // not need a joined Citra peer: the announce gate, the station requirement
    // and the kind-0/1 check decide instead.  V-265: the argument is the whole
    // UDS frame (LLC + UDS header + payload), because the room proxy channel
    // carries frames; only the identity words are substituted.
    std::vector<ControlEmission> on_citra_game_payload(const citra_room::Bytes& frame);
    // Gateway counted an opaque data frame that stayed on the G-b path.
    void note_opaque_data();
    // Gateway dropped an LDN packet because this session is not the owner.
    void note_non_owner_ignored();

    // Yuzu side inbound LDN body (section 5 length gates included).
    LdnHandling on_ldn(const room_client::LdnPacket& packet, const LdnContext& context);

    // Mirror a state change that the owner already validated.  Output is
    // discarded and counted (mirror_applied / mirror_suppressed).
    void mirror_connect(const room_client::IPv4& from, const citra_room::MacAddress& station_mac,
                        const std::array<std::uint8_t, 4>& declared_ipv4, bool have_declared_ipv4,
                        const citra_control::UserNameBytes& user_name = {},
                        std::int16_t version = kControlVersion);
    void mirror_disconnect(const room_client::IPv4& from);
    void mirror_destroy();

    bool ap_established() const;
    bool citra_connected() const;
    // V-131: the Citra guest alone has associated (Authentication SEQ1/SEQ2,
    // AssociationResponse and EAPoL-Start).  A gateway-only room has no Yuzu
    // peer, so ControlPlane::connected() never turns true there; the synthetic
    // host's game-layer dialogue is keyed to this instead (gc6 replayed
    // nothing because the script never armed).
    bool citra_association_complete() const;
    std::size_t station_count() const;
    const std::vector<ControlStation>& stations() const;
    std::optional<ControlStation> game_return_station(const room_client::IPv4& fake_ip) const;
    bool gu_host_source(const room_client::IPv4& source) const;
    void set_gu_host_native_members(const std::vector<room_client::IPv4>& members);
    bool gu_native_peer_source(const room_client::IPv4& source) const;
    std::vector<ControlEmission> on_gu_native_peer_proxy(
        const room_client::IPv4& source, const citra_room::Bytes& plain);
    std::vector<ControlEmission> on_gu_native_peer_game(const citra_room::WifiPacket& wifi);
    std::optional<GuHostGuestIdentity> gu_host_guest_identity() const;
    void set_gu_host_guest_identities(const std::vector<GuHostGuestIdentity>& peers);
    std::optional<citra_room::Bytes> translate_gu_host_announcement(
        const room_client::IPv4& source, const citra_room::Bytes& plain) const;
    std::vector<ControlEmission> on_gu_host_proxy(
        const room_client::IPv4& source, const citra_room::Bytes& plain);
    std::vector<ControlEmission> on_gu_host_guest_game(const citra_room::WifiPacket& wifi);
    bool accepts_gu_host_peer_wifi(const citra_room::WifiPacket& wifi) const;
    // V-277: not const — a well-formed MHGU join request teaches the bridge the
    // requester endpoint and short id that the accept expansion replays.
    std::optional<citra_room::Bytes> translate_game_return(const citra_room::Bytes& plain);
    std::optional<citra_room::Bytes> translate_game_return(
        const room_client::IPv4& source, const citra_room::Bytes& plain);
    void invalidate_game_return_admission();
    // V-243: cross-game session phase (ApStandby / StationAdmitted /
    // HallPresented).  Passive recording; no behaviour reads it yet.
    const char* session_phase() const;
    // V-245: feed one 32AB9864 packet observation (from a decompressed inbound
    // ProxyPacket) into the rolling heartbeat window; learns the mirrored pair
    // per the measured V-242 signature.  Metadata only -- never forwards.
    void observe_heartbeat(const std::array<std::uint8_t, 4>& sender, std::uint8_t kind,
                           std::uint16_t seq, std::uint16_t rel_time, std::uint16_t time_echo);
    // True once the rolling window currently yields the mirrored pair.
    bool heartbeat_pair_learned() const;
    const citra_room::MacAddress& bssid() const;
    std::uint32_t room_seed() const;
    std::uint32_t wlan_comm_id() const;
    std::uint32_t network_id() const;
    std::uint64_t beacon_count() const;
    // V-267: what the LDN side currently advertises from the Citra peer -- the
    // stored appdata (empty when none is usable or the gate is off) and the MAC
    // the Beacon came from.  Diagnostic only: no behaviour reads them.
    const std::vector<std::uint8_t>& citra_advertise_appdata() const;
    const citra_room::MacAddress& citra_advertise_source_mac() const;

    const std::map<std::string, std::uint64_t>& counters() const;
    std::string counters_json() const;
    std::string diag_text() const;
    // V-261: bounded per-verdict Data frame samples (at most four per verdict).
    const std::map<std::string, std::vector<DataFrameSample>>& data_frame_samples() const;
    std::string data_frame_samples_json() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// The complete counter key set (all keys always present in counters_json()).
const std::vector<std::string>& control_counter_keys();

// Same key set as counters_json(), with absent keys rendered as 0.  The gateway
// uses it to merge every session's control counters into one "control" object.
std::string control_counters_json(const std::map<std::string, std::uint64_t>& counters);

} // namespace citra_gateway
