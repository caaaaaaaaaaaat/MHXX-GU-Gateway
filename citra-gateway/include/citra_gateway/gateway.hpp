// SPDX-License-Identifier: GPL-2.0-or-later
// G-b loopback gateway: N Citra v4 clients (one ENet/UDP peer each, exactly like
// a real Citra room member: citra-master/src/network/room_member.cpp) <-> N Yuzu
// v1 room peers, each backed by one frozen room_transport::Transport.
//
// The A/B acceptance harness may still drive the legacy TCP + 4-byte
// big-endian length-prefix listener through Options::citra_tcp_test_transport;
// that framing is test-only and is not reachable from the CLI (see README.md
// "Transports" and docs/citra-gateway-report.md section 14).
//
// The gateway terminates each side's native room protocol locally (ADR-015):
// only Citra IdWifiPacket(frame_type=Data) <-> Yuzu IdProxyPacket crosses, all
// other ids/enums are rejected and counted. Nothing here is a game-data
// translation; see README.md and docs/citra-gateway-report.md.
#pragma once

#include "citra_gateway/capabilities.hpp"
#include "citra_gateway/control.hpp"
#include "citra_gateway/identity.hpp"
#include "citra_gateway/trace.hpp"
#include "room_transport/transport.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace citra_gateway {

enum class ClientPhase { Framing, Joining, Joined, Closing, Closed };
std::string phase_name(ClientPhase phase);

struct Options {
    // Desktop may explicitly enable other IPv4 bindings; CLI stays loopback-only.
    bool allow_remote_listen = false;
    std::string listen_address = "127.0.0.1";
    std::uint16_t listen_port = 24873;
    std::string room_address = "127.0.0.1";
    std::uint16_t room_port = 24872;
    // Desktop application explicitly enables numeric remote room connections.
    bool allow_remote_room = false;
    // V-016l: the room password this gateway enforces itself for the Citra side.
    // Citra checks the password before nickname/MAC/console id/version
    // (citra-master/src/network/room.cpp:331-334), so the gateway must compare it
    // locally to answer with the same code when two faults are present. The value
    // is still forwarded unchanged in the Yuzu v1 join request.
    std::string room_password;
    // V-016l: known room capacity (member_slots) used for the local room-full
    // check Citra performs before checking anything else
    // (citra-master/src/network/room.cpp:305-308). In the in-process mode the host
    // reads Network::Room::GetRoomInformation().member_slots. 0 means "unknown":
    // the gateway then cannot place the room-full check before the others and the
    // report records that the external-server mode only guarantees a subset.
    std::uint32_t room_capacity = 0;

    std::uint32_t connect_timeout_ms = 1500;
    std::uint32_t join_timeout_ms = 1500;
    std::uint32_t leave_timeout_ms = 500;
    // Gateway-side watchdog for one join; must exceed the two transport timers.
    std::uint32_t join_watchdog_ms = 6000;

    std::size_t max_clients = 254;
    std::size_t max_frame_bytes = 65536;          // Citra frame hard cap (both transports)
    // V-023: this guard is NOT Network::MaxMessageSize. The upstream 500 byte
    // constant (citra-master/src/network/room.h:20) only truncates chat broadcasts
    // (citra-master/src/network/room.cpp:913-914); the frozen codec's data plane
    // limit is citra_room::Limits::data_bytes (60000) and its whole frame limit is
    // citra_room::Limits::packet_bytes (65536). The pre decode guard therefore
    // defaults to the codec frame limit, never to 500, and stays configurable with
    // --max-inbound-citra <bytes>.
    std::size_t max_inbound_citra_bytes = citra_room::Limits{}.packet_bytes;
    std::size_t per_client_inbox_bytes = 262144;
    std::size_t per_client_outbox_bytes = 262144;
    std::size_t per_client_outbox_frames = 256;

    std::size_t room_queue_packets = 128;
    std::size_t room_queue_bytes = 262144;
    std::size_t room_outgoing_packets = 64;
    std::size_t room_outgoing_bytes = 262144;
    std::size_t proxy_compressed_bytes = 65536;
    std::size_t proxy_decompressed_bytes = 65536;

    std::uint32_t close_grace_ms = 500;
    std::size_t capture_limit = 64;
    std::size_t event_limit = 4096;

    // Gateway-declared Yuzu-side peer identity, sent as IdSetGameInfo after join.
    std::string peer_game_name = "CitraGateway";
    std::uint64_t peer_game_id = 0;
    std::string peer_game_version = "gw-v1";

    // Declared placeholders (ADR-015): ports have no Citra counterpart and the
    // Citra channel has no Yuzu counterpart.
    std::uint16_t proxy_port_placeholder = 0;
    // V-272: port stamped on every translated ProxyPacket.  The Yuzu
    // ProxySocket drops a packet whose remote port differs from its own local
    // port (socket_proxy.cpp HandleProxyPacket), and MHGU binds 12345, so a
    // forwarded frame must carry that port instead of the 0 placeholder.
    // 0 keeps the old placeholder behaviour (tests, frozen evidence).
    std::uint16_t proxy_udp_port = 0;
    std::uint8_t wifi_channel_placeholder = 0;
    int zstd_level = 1;
    // G-b' (docs/M4-CONTROL-PLANE.md section 7): when true, every joined Citra
    // session gets its own ControlBridge, which owns the LDN/UDS control plane
    // through the citra-control library. Default false keeps the frozen G-b
    // evidence (data-plane only) byte-for-byte unchanged.
    bool control_plane_enabled = false;
    // V-259: cross-game announce forward (see control.hpp LdnIdentityPair).
    bool ldn_announce_forward = false;
    // V-266: reverse UDS association injection -- present every admitted Yuzu
    // station to Citra as a joining UDS guest so Citra's node_map gains the entry
    // MHXX needs (see control.hpp ControlOptions::ldn_guest_inject).  Control
    // plane only; main.cpp refuses the combination without --control-plane.
    bool ldn_guest_inject = false;
    // V-274: experimental MH control return path for admitted/injected Yuzu
    // stations. Requires an observed Citra host SecureData channel pair.
    // Off preserves the opaque room relay and its existing trust boundary.
    bool ldn_game_return = false;
    struct LdnIdentityPair {
        std::array<std::uint8_t, 4> xx_word{};
        std::array<std::uint8_t, 4> gu_word{};
    };
    std::vector<LdnIdentityPair> ldn_identity_pairs;
    // V-047/V-048: transport-only passthrough for Citra<->Citra sessions. The
    // default gateway translates the data plane and owns the control plane, so
    // every non-Data WifiPacket (Beacon, Authentication, NodeMap, ...) is dropped
    // with payload_rejected_unknown_category and a Citra client can never
    // discover a room. With this option the gateway forwards every WifiPacket
    // type unchanged, exactly like the dumb citra-room.exe relay. Default false
    // keeps the frozen evidence byte-for-byte unchanged.
    bool citra_peer_relay = false;
    // Bounded G-b' emitted-frame log (test-only observation of what the
    // gateway actually put on the wire for control-plane events).
    std::size_t emitted_limit = 256;
    // V-111 (docs/G4-UDS-BEACON-PROFILE-SPEC.md): opt-in UDS beacon identity
    // profile, copied into every per-session ControlOptions.  Real MHXX hosts
    // advertise a fixed identity (wlan_comm_id 0x00197110, id 0, attributes
    // 0x8000, network_id 0, the word 0x0001 after max_nodes) plus 200 bytes of
    // application data; the derived gateway values differ in every one of those
    // fields, and MHXX will not list a hall whose beacon does not match.  All
    // flags default to false, so without the CLI options the emitted beacon bytes
    // are exactly what the G3/D2/D3 acceptance recorded.
    std::uint32_t uds_wlan_comm_id = 0;
    bool have_uds_wlan_comm_id = false;
    // V-239: cross-game LDN identity override.  A real Yuzu client filters
    // ScanResp by IntentId.local_communication_id (01052024 mirror
    // lan_discovery.cpp:127-131) and MHGU advertises 0x0100770008dd8000 on its
    // own AP (measured in .private-runtime/evidence/g2-run2); the derived
    // mix32 value (citra-control/src/map.cpp) can never match it, so a real
    // MHGU client silently drops every gateway ScanResp.  0 keeps the derived
    // value and byte-for-byte pre-V-239 behaviour.
    std::uint64_t ldn_comm_id_override = 0;
    // Stable non-zero LDN session for the override path; 0 derives one from the
    // room seed (a zero session never appears on a real AP).
    std::uint64_t ldn_session_id = 0;
    // V-239: game advertise data for ScanResp/SyncNetwork (see control.hpp).
    std::vector<std::uint8_t> ldn_advertise_data;
    // V-267: advertise the Citra peer's *live* UDS beacon application_data in
    // ScanResp/SyncNetwork whenever one has been received, and use
    // ldn_advertise_data only as the fallback (see
    // control.hpp ControlOptions::ldn_live_advertise).  Default true -- that is
    // the point of the bridge -- and --no-ldn-live-advertise restores the
    // pre-V-267 bytes exactly.
    bool ldn_live_advertise = true;
    bool ldn_require_live_hall = false;
    bool ldn_gu_host_discovery = false;
    bool ldn_gu_host_admission = false;
    bool ldn_dual_host = false;
    std::uint8_t uds_beacon_id = 0;
    bool have_uds_beacon_id = false;
    std::uint16_t uds_attributes = 0;
    bool have_uds_attributes = false;
    std::uint32_t uds_network_id = 0;
    bool have_uds_network_id = false;
    std::uint16_t uds_tag_word = 0;
    bool have_uds_tag_word = false;
    // Channel of the WifiPacket the gateway wraps a synthesized Citra frame in
    // (0 keeps kControlChannel).  Real MHXX beacons are seen on channel 11.
    std::uint16_t uds_wifi_channel = 0;
    bool have_uds_wifi_channel = false;
    std::vector<std::uint8_t> uds_appdata;
    bool have_uds_appdata = false;
    // V-111/D4: identity of the synthetic host record (UDS node 1).
    std::uint64_t uds_host_seed = 0;
    bool have_uds_host_seed = false;
    citra_control::Username uds_host_username{};
    bool have_uds_host_username = false;
    // V-112 (experimental, synthetic-host topology): one host-side game-layer
    // frame (LLC + Nintendo SecureData header + game payload) that the gateway
    // emits to an already connected Citra client.  A real MHXX host answers a
    // guest's EAPoL-Start with game-layer traffic on EtherType 0x876d, and the
    // guest waits for it before it enters the gathering hall, so a synthetic
    // host has to synthesize that traffic as well.  The script is a replay of a
    // captured host dialogue (.verify-v111, see the spec) and stays empty by
    // default, which leaves the gateway byte-for-byte unchanged.
    struct GameScriptStep {
        // 0: fire delay_ms after the client reaches the control plane's
        // Connected state (its EAPoL-Start).  N > 0: fire delay_ms after the
        // N-th game-layer frame arrived from the client.
        std::uint32_t after_guest_frames = 0;
        std::uint32_t delay_ms = 0;
        // True: address the frame to the broadcast MAC, false: to the client.
        bool broadcast = true;
        // The UDS payload exactly as it appears after Citra's 19 byte room
        // frame header (LLC + SecureData header + payload).
        std::vector<std::uint8_t> payload;
        // Free-form label copied into events/counters (usually the length).
        std::string label;
    };
    std::vector<GameScriptStep> game_script;
    // V-132 (experimental, synthetic-host topology): MHXX carries two 32 bit
    // counter families inside the 0x876d payload.  The guest picks one (call it
    // A) and announces it in its own frames; the host echoes *that* value back.
    // The host picks the other (B) and the guest echoes it.  A byte-for-byte
    // replay therefore echoes the captured session's A to a guest that chose its
    // own A, which no real host ever does (gc8: the guest announced 9409deb8 while
    // the replay echoed c9c93d03, and the join collapsed 266 ms after WakeUp).
    // When have_game_nonce_ref is set the gateway rewrites every occurrence of
    // game_nonce_ref + k (k in [0, 31]) in a replayed step with the guest's live
    // value, and holds a step that needs the rewrite until the guest announces it.
    bool have_game_nonce_ref = false;
    std::uint32_t game_nonce_ref = 0;
    // V-133 (experimental, synthetic-host topology): MHXX's guest also picks the
    // session token families C and D, and the real host echoes the live values at
    // fixed places in its own dialogue (measured on the 083801 and 085518
    // sessions: C in the 196/332 byte host frames, D in the 268 byte one).  A
    // byte-for-byte replay therefore echoed the captured session's values; gc9's
    // guest announced 6e23a8c1 for C, never saw it echoed and abandoned the join
    // 18 ms later without ever sending its phase transition frame.  Each entry
    // names the captured value and the guest-frame sites that announce its live
    // value as <game data length>:<offset>; a step carrying a captured value is
    // held until the live value is known, exactly like the nonce family above.  A
    // replacement also rewrites the two byte suffix <value >> 16> when it follows
    // the value, because the captured encoding is <value><value >> 16>.
    struct GameTokenRef {
        std::uint32_t ref = 0;
        std::vector<std::pair<std::size_t, std::size_t>> learn_sites;
    };
    std::vector<GameTokenRef> game_token_refs;
    // HARNESS ONLY, and not reachable from the CLI: when true the Citra side is
    // served by the legacy TCP listener with 4-byte big-endian length-prefix
    // framing, which the deterministic A/B groups drive. When false (the
    // default, and what citra-gateway.exe always uses) the Citra side is an
    // ENet/UDP server with one channel and no length prefix, which is the
    // transport a real Citra room member speaks (V-027).
    bool citra_tcp_test_transport = false;

    // G2 trace recording for channels A/B/C (docs/G2-PROCEDURE.md section 3). Opt-in:
    // an empty trace_path (the default) leaves the gateway byte-for-byte
    // unchanged. When set, open() creates/truncates the file and every frame
    // crossing the gateway is appended as one JSON object per line. The path is
    // caller-supplied and normally lives outside the repository (ADR-007: the
    // repo never holds raw captures).
    std::string trace_path;
    // Include each frame's raw bytes as lower-case hex. Off by default: records
    // then carry only the length and the SHA-256 of the raw bytes.
    bool trace_raw = false;
    // Run identity copied into every record (manifest_id/run_id/channel/
    // platform/build_id/role/stage). Injected here, never read by the builder.
    TraceContext trace_context;
    // Optional injected stamp source. When empty the gateway reads the real
    // UTC/steady clocks; tests inject a fixed stamp so an entire record is
    // deterministic. Consulted only while tracing is enabled.
    std::function<TraceStamp()> trace_clock;
    // Optional stage file. When set, the gateway reads it at open and once per
    // tick; a content change updates the run stage and appends one stage.begin
    // marker. An unreadable/absent file keeps the previous stage and never
    // changes cross-plane protocol behaviour.
    std::string trace_stage_file;
    // Explicit startup requests only. Legacy behavior is NOT MH application conversion.
    ApplicationMode application_mode = ApplicationMode::LegacyTransport;
    ProxyWireProfile proxy_wire_profile = ProxyWireProfile::Mirror01052024;
};

struct Counters {
    std::uint64_t clients_accepted = 0;
    std::uint64_t clients_rejected_full = 0;
    std::uint64_t clients_rejected_local = 0;
    std::uint64_t clients_joined = 0;
    std::uint64_t clients_left = 0;
    std::uint64_t clients_closed_by_gateway = 0;

    std::uint64_t frames_in = 0;
    std::uint64_t frames_out = 0;
    std::uint64_t frames_rejected = 0;
    // V-112: SecureData (EtherType 0x876d) frames the synthetic host emitted
    // from Options::game_script.
    std::uint64_t game_script_frames_sent = 0;
    // V-132: the guest-chosen nonce family (A).  game_script_nonce_learned counts
    // distinct values picked up from the guest, frames_patched counts replayed
    // frames rewritten with the live value and nonce_waits counts steps that were
    // held because the guest had not announced A yet.
    std::uint64_t game_script_nonce_learned = 0;
    std::uint64_t game_script_frames_patched = 0;
    std::uint64_t game_script_nonce_waits = 0;
    // V-133: the extra guest-chosen token families.  tokens_learned counts
    // distinct announced values, token_frames_patched counts replayed frames
    // rewritten with a live value and token_waits counts steps held because a
    // captured value had not been announced yet.
    std::uint64_t game_script_tokens_learned = 0;
    std::uint64_t game_script_token_frames_patched = 0;
    std::uint64_t game_script_token_waits = 0;
    std::uint64_t prefix_truncation_rejections = 0;
    std::uint64_t wrong_direction_rejections = 0;
    std::uint64_t unknown_id_rejections = 0;
    std::uint64_t unknown_enum_rejections = 0;
    std::uint64_t trailing_byte_rejections = 0;
    std::uint64_t malformed_frame_rejections = 0;
    // V-023: frozen codec limit violations (data over Limits::data_bytes, chat
    // over Limits::chat_bytes), kept apart from policy driven frame caps.
    std::uint64_t limit_exceeded_rejections = 0;
    std::uint64_t oversize_rejections = 0;
    std::uint64_t sentinel_mac_rejections = 0;
    std::uint64_t unsupported_in_phase_rejections = 0;

    std::uint64_t local_version_rejections = 0;
    std::uint64_t local_mac_collision_rejections = 0;
    std::uint64_t local_console_id_collision_rejections = 0;
    // V-016g: rejections whose Citra semantic has no Yuzu counterpart (today this
    // is exactly Citra IdConsoleIdCollision, which Yuzu has no notion of).
    std::uint64_t no_correspondence_rejections = 0;
    std::uint64_t local_closing_rejections = 0;
    std::uint64_t local_join_rejections = 0;
    // V-016l: local replicas of the Citra server's own join checks, in the order
    // Citra performs them (room full -> password -> nickname -> MAC -> console id
    // -> version). The multi-fault ordering tests assert exactly one of these.
    std::uint64_t local_room_full_rejections = 0;
    std::uint64_t local_wrong_password_rejections = 0;
    std::uint64_t local_name_collision_rejections = 0;

    std::uint64_t room_join_attempts = 0;
    std::uint64_t room_join_successes = 0;
    std::uint64_t room_join_failures = 0;
    std::uint64_t room_errors_mapped = 0;
    std::uint64_t room_errors_unmapped = 0;
    std::uint64_t room_transport_failures = 0;
    std::uint64_t room_frames_rejected = 0;
    std::uint64_t join_watchdog_timeouts = 0;

    std::uint64_t transport_boundary_rejections = 0;
    std::uint64_t proxy_frames_emitted = 0;   // citra -> room Zstd compression ok
    std::uint64_t proxy_frames_consumed = 0;  // room -> citra Zstd decompression ok
    std::uint64_t payload_forwarded = 0;
    std::uint64_t payload_rejected_unknown_category = 0;
    std::uint64_t payload_rejected_boundary = 0;
    std::uint64_t payload_rejected_source = 0;
    std::uint64_t payload_rejected_destination = 0;
    std::uint64_t channel_normalized = 0;
    // V-047/V-048 peer relay. Emitted/consumed count forwarded WifiPackets that
    // carried the CRLY wrapper; bad_wrapper counts wrapped frames that could not
    // be restored (short header, unknown version, out-of-range frame type). All
    // three are identically 0 while citra_peer_relay is false.
    std::uint64_t peer_relay_frames_emitted = 0;
    std::uint64_t peer_relay_frames_consumed = 0;
    std::uint64_t peer_relay_bad_wrapper = 0;
    // v4 SetGameInfo is a declared category with a translation: ADR-009 pins one
    // Citra client to one v1 room peer, so the game info is written to that
    // session's own room peer. The v1 GameInfo.version field has no v4 source and
    // is filled from the gateway placeholder (counted, never silently).
    std::uint64_t set_game_info_accepted = 0;
    std::uint64_t set_game_info_deferred = 0;
    std::uint64_t set_game_info_replaced = 0;
    std::uint64_t set_game_info_discarded = 0;
    std::uint64_t set_game_info_rejected = 0;
    std::uint64_t set_game_info_version_placeholder = 0;
    // Non-broadcast Citra destination MAC with no session mapping: rejected.
    std::uint64_t destination_unmapped_rejections = 0;

    std::uint64_t self_echo_rejections = 0;
    std::uint64_t unknown_source_rejections = 0;
    std::uint64_t queue_overflows = 0;
    std::uint64_t outbox_overflows = 0;
    std::uint64_t inbox_overflows = 0;

    std::uint64_t mac_generated = 0;
    std::uint64_t ip_reassigned = 0;
    std::uint64_t unmappable_room_members = 0;
    std::uint64_t projection_missing_self = 0;
    std::uint64_t port_conflicts = 0;
    std::uint64_t events_dropped = 0;

    // Citra-side transport counters (G-c / V-028). The deliverable Citra
    // listener is an ENet/UDP server: one ENet peer per session, one channel,
    // raw citra_room v4 messages with no length prefix. citra_tcp_accepts
    // stays 0 unless the test-only TCP listener is enabled.
    std::uint64_t citra_enet_connects = 0;
    std::uint64_t citra_enet_disconnects = 0;
    std::uint64_t citra_enet_receives = 0;
    std::uint64_t citra_enet_rejected_full = 0;
    std::uint64_t citra_tcp_accepts = 0;

    std::uint64_t members_in_room = 0;
    std::uint64_t max_members_in_room = 0;

    std::map<std::string, std::uint64_t> decode_error_codes;
    std::map<std::string, std::uint64_t> error_map_hits;

    std::uint64_t room_version_forwarded = room_client::network_version;
    std::uint64_t citra_version_served = citra_room::network_version;
};

struct ClientSnapshot {
    std::uint64_t id = 0;
    std::string nickname;
    std::string phase;
    // "enet" (deliverable Citra transport) or "tcp" (test-only harness path).
    std::string transport;
    bool mac_known = false;
    std::string mac;
    bool ip_known = false;
    std::string fake_ip;
    std::string room_state;
    std::string failure;
    std::uint64_t frames_in = 0;
    std::uint64_t frames_out = 0;
    std::uint64_t frames_rejected = 0;
    std::uint64_t room_frames_rejected = 0;
    std::uint64_t transport_boundary_rejections = 0;
    std::size_t queued_out_bytes = 0;
};

// Test-only observation of one declared data-plane frame. Never game data:
// every payload in G-b is synthetic.
struct DataPlaneCapture {
    std::string direction;      // "citra_to_room" | "room_to_citra"
    std::uint64_t client_id = 0;
    bool broadcast = false;
    std::string source_mac;
    std::string destination_mac;
    std::string source_ip;
    std::string destination_ip;
    std::size_t wire_bytes = 0;     // ProxyPacket.data size (single Zstd frame)
    std::size_t content_bytes = 0;  // ZSTD frame content size
    std::size_t opaque_bytes = 0;   // Citra WifiPacket.data size
    std::string opaque_hex;         // first 512 payload bytes, lower-case hex
};

struct Event {
    std::uint64_t seq = 0;
    std::uint64_t time_ms = 0;
    std::string kind;
    std::uint64_t client_id = 0;
    std::string detail;
};

// G-b' test-only observation of one frame the gateway emitted because of a
// control-plane event. `hex` is the exact byte sequence handed to the frozen
// room transport (room direction) or to the Citra client (citra direction).
struct EmittedFrame {
    std::uint64_t seq = 0;
    std::uint64_t time_ms = 0;
    std::uint64_t client_id = 0;
    std::string direction;  // "citra" | "room"
    std::string kind;       // e.g. "citra.beacon", "room.sync_network"
    std::size_t bytes = 0;
    std::string hex;        // lower-case hex, whole frame
};

class Gateway {
public:
    explicit Gateway(Options options = {});
    ~Gateway();
    Gateway(const Gateway&) = delete;
    Gateway& operator=(const Gateway&) = delete;

    // Binds the Citra-side listener (loopback unless explicitly enabled): an ENet/UDP host (the deliverable
    // transport, one channel) or, with the harness-only
    // Options::citra_tcp_test_transport, the legacy TCP listener. Throws
    // std::runtime_error when a non-loopback address is not enabled or the port cannot be
    // bound (explicit port conflict failure, never a silent fallback).
    void open();
    // Non-blocking, bounded work: accept, per-client I/O, per-client room poll.
    void tick(std::uint32_t wait_ms = 0);
    void close() noexcept;
    // Declares "the room is closing": every later Citra join is answered with
    // Citra CloseRoom (11) locally, matching Room::SendCloseMessage semantics.
    void begin_shutdown() noexcept;

    bool is_open() const noexcept;
    std::uint16_t port() const noexcept;
    // G2 trace: true while a trace file is open.
    bool trace_enabled() const noexcept;
    // G2 trace: the effective run identity as one JSON object (enabled, raw
    // switch, trace path and the manifest_id/run_id/channel/platform/build_id/
    // role/stage copied into every record).
    std::string trace_json() const;

    Counters counters() const;
    std::vector<ClientSnapshot> clients() const;
    std::vector<IdentityEntry> identities() const;
    std::vector<DataPlaneCapture> data_plane_captures() const;
    std::vector<Event> events() const;
    std::size_t client_count() const;

    std::string counters_json() const;
    // V-261: free-form diagnostic (contains the merged control counters and the
    // bounded Data frame samples).  Main writes it to diag.json in --dump; the
    // announce forward cannot be diagnosed from counters.json alone because the
    // control counters live per session.
    std::string diag_text() const;
    // V-262: bounded per-frame-type samples of every Wi-Fi frame the gateway
    // received from the Citra wire, plus per-type counts.  Main writes it to
    // inbound.json; it tells a real run whether the Citra client is acting as the
    // UDS host (beacons) and carries the beacon application data verbatim.
    std::string inbound_json() const;
    std::string clients_json() const;
    std::string identities_json() const;
    std::string captures_json() const;
    std::string events_json() const;
    std::string snapshot_json() const;

    // Test-only: feed one room-side frame into one client's frozen transport and
    // run the gateway handling path. Used to exercise the gateway-owned member
    // table and the room-side boundary from inside this tree.
    bool inject_room_message_for_test(std::uint64_t client_id, const room_client::Message& message);
    bool inject_room_raw_for_test(std::uint64_t client_id, const room_client::Bytes& raw_frame);

    // G-b' test-only observation: every frame the gateway emitted through the
    // control-plane bridge (bounded, oldest dropped first).
    const std::vector<EmittedFrame>& emitted_frames() const;
    std::string emitted_json() const;
    void clear_emitted_for_test();

    // G-b' test-only injection that does not depend on transport timing.
    // Both feed the *decoded* gateway handling path: inject_citra_frame_for_test
    // decodes one Citra Server/ClientToServer frame as if it had arrived from
    // that client, and inject_ldn_message_for_test hands one decoded room-side
    // LdnPacket to the gateway-owned LDN handling. Emissions are recorded; no
    // peer receives anything.
    bool inject_citra_frame_for_test(std::uint64_t client_id, const citra_room::Bytes& frame);
    bool inject_ldn_message_for_test(std::uint64_t client_id, const room_client::LdnPacket& packet);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// Fail-closed single-frame Zstd gate with the same semantics as the frozen M2
// transport boundary, re-implemented here so this tree can test it directly.
bool valid_proxy_frame(const room_client::Bytes& frame, std::size_t compressed_cap,
                       std::size_t decompressed_cap, std::string* why);

// One standard Zstd frame with a known content size, bounded by compressed_cap.
bool compress_proxy_frame(const citra_room::Bytes& plain, std::size_t compressed_cap,
                          int level, room_client::Bytes& out, std::string* why);

// Decompresses exactly one previously validated single frame.
bool decompress_proxy_frame(const room_client::Bytes& frame, std::size_t decompressed_cap,
                            citra_room::Bytes& out, std::string* why);

// The nickname rule both room servers apply: ^[ a-zA-Z0-9._-]{4,20}$
// (citra-master/src/network/room.cpp IsValidNickname and the identical Yuzu rule
// at 01052024-yuzu-mirror-master/src/network/room.cpp:550-560). Exposed so the
// harness can cross-check it against citra_room::is_valid_nickname.
bool is_valid_nickname(const std::string& nickname);

} // namespace citra_gateway
