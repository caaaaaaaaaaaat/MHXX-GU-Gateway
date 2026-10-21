// SPDX-License-Identifier: GPL-3.0-or-later
// citra-control - control-plane state machine (docs/M4-CONTROL-PLANE.md §4,
// plus docs/VERIFICATION-LOG.md V-016k, V-016n and V-016o).
//
// Folding rule: the Citra side's three-frame association
// (Authentication SEQ1 -> SEQ2 -> AssociationResponse) plus the EAPoL-Start
// exists ONLY as gateway-internal state; the only LDN bodies the gateway ever
// originates are ScanResp and SyncNetwork, and the only 802.11 frames it ever
// originates are the Citra-side ones.  There is no code path that forwards one
// wire's native frame to the other wire; guard_no_cross_side_leak() exists so a
// caller can assert that invariant explicitly and count the refusal, and
// validate_outbox() checks the same property over the queued obligations.
//
// V-016n rules encoded here:
//  (1) SendPacket(type,data,remote_ip) is broadcast=false and carries
//      remote_ip; SendBroadcast(type,data) is broadcast=true and carries no
//      remote_ip.  LdnIntent models exactly one of the two forms.
//  (2) after every Connect/Disconnect the access point pushes SyncNetwork to
//      every connected client (lan_discovery.cpp:369-385 UpdateNodes).
//  (3) bssid/node MAC stability comes from the SessionMap bijection.
//  (4) node_count = connected clients + 1 (the host).
//
// V-016o requirements encoded here:
//  (5) "AP established" gate (docs/M4-CONTROL-PLANE.md §4.1 requirement 1): the
//      gateway answers a Yuzu Scan with ScanResp ONLY while its LDN access point
//      is in ApState::Created, and it accepts Connect only in that state.  The
//      gate is explicit and test-locked instead of being an implicit caller
//      assumption: the intended deployment always runs the gateway in
//      ApState::Created, and a caller that has not got there gets
//      Err::IllegalState plus the scan_resp_no_ap / connect_no_ap counters
//      instead of a silent ScanResp.
//  (6) Ordered emission obligations are first-class: every event appends tagged
//      OutIntent values to the outbox, on the wire that must consume them.
//      Authentication SEQ1 yields [AuthSeq2, AssocResponse] in that fixed order;
//      EAPoL-Start yields [NodeMap(broadcast), Logoff(broadcast)]; a refused
//      association outcome yields NO Citra-frame obligation at all (V-016k:
//      citra-master/src/core/hle/service/nwm/nwm_uds.cpp:165-169 ASSERTs on a
//      non-successful association result and ASSERT has no NDEBUG guard, so a
//      real client would Crash()).  The library never sends anything itself; it
//      only models the obligations.
//  (7) Determinism: SyncNetwork obligations are pushed in client insertion
//      order (the order in which peers connected, i.e. clients_[0], clients_[1],
//      ...).  yuzu_connect appends the new client before syncing, so the new
//      client is the LAST SyncNetwork of that batch, matching UpdateNodes
//      iterating connected_clients in order.  A gateway that keeps its room
//      member table in the same insertion order therefore sees identical order.
//      Every unicast LDN obligation carries that peer's fake IPv4 address and is
//      never 0.0.0.0; every broadcast obligation carries no address at all.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "citra_control/bytes.hpp"
#include "citra_control/ldn_ctrl.hpp"

namespace citra_control {

enum class Side { Citra, Yuzu };

// Exactly one of the two Yuzu LDN send forms (V-016n rule 1).
struct LdnIntent {
    LdnPacketType type = LdnPacketType::Scan;
    bool broadcast = false;                   // SendBroadcast => true, no remote_ip
    std::array<std::uint8_t, 4> remote_ip{};  // SendPacket => false + remote_ip
};

Err validate_ldn_intent(const LdnIntent& intent, Diag* diag = nullptr);

// The LDN access point state this gateway models; the names follow the yuzu LDN
// State enum (ldn_types.h: State::None/Initialized/AccessPointOpened/
// AccessPointCreated).  Only ApState::Created means "the AP exists and can be
// discovered", because only then is there a NetworkInfo to advertise.
enum class ApState { Down, Initialized, Opened, Created };

const char* ap_state_name(ApState state) noexcept;

// V-243: session-scoped phase for the cross-game state machine
// (docs/MH-SESSION-CONVERSION-STATE-MACHINE.md).  Passive recording only --
// no branch in this class reads it; transitions advance it so the gateway can
// expose and dump the phase without changing any existing behaviour.
//   ApStandby       the AP is established and answers Scans (V-239 proven)
//   StationAdmitted at least one Yuzu client has connected (V-240 proven)
//   HallPresented   reserved: heartbeat-pair learning completed (not reached yet)
enum class SessionPhase { ApStandby, StationAdmitted, HallPresented };

const char* session_phase_name(SessionPhase phase) noexcept;

// The association result the gateway is willing to serve.  Anything other than
// Successful produces no frame obligations and is counted (V-016k).
enum class AssocOutcome { Successful, Refused };

// The Citra-side 802.11/EAPoL frames the gateway may originate.  These are the
// only frame kinds that can appear in an OutIntent; there is no value for the
// Yuzu side's native messages.
enum class CitraFrameKind { AuthSeq2, AssocResponse, NodeMap, Logoff };

const char* citra_frame_kind_name(CitraFrameKind kind) noexcept;

struct CitraFrameIntent {
    CitraFrameKind kind = CitraFrameKind::AuthSeq2;
    bool broadcast = false;  // NodeMap and Logoff are broadcast, the other two are not
};

// One queued obligation, tagged with the wire that must consume it.  An
// OutIntent is never valid for both wires: is_ldn() xor is_citra().
struct OutIntent {
    Side side = Side::Yuzu;
    LdnIntent ldn{};
    CitraFrameIntent citra{};

    bool is_ldn() const noexcept { return side == Side::Yuzu; }
    bool is_citra() const noexcept { return side == Side::Citra; }
};

enum class CitraState { Idle, Beacon, Authenticating, Associating, Connected, LoggedOff };
enum class YuzuState { Idle, Scanned, Connecting, Synced, Connected, Disconnected };

const char* citra_state_name(CitraState state) noexcept;
const char* yuzu_state_name(YuzuState state) noexcept;

// The folded Citra association.  Never exposed as an LDN body.
struct CitraAssociation {
    bool auth_seq1 = false;
    bool auth_seq2 = false;
    bool assoc_response = false;
    bool eapol_start = false;
    bool complete() const noexcept { return auth_seq1 && auth_seq2 && assoc_response && eapol_start; }
    void clear() noexcept {
        auth_seq1 = false;
        auth_seq2 = false;
        assoc_response = false;
        eapol_start = false;
    }
};

class ControlPlane {
public:
    ControlPlane() = default;

    void reset(Diag* diag = nullptr) noexcept;

    CitraState citra_state() const noexcept { return citra_; }
    YuzuState yuzu_state() const noexcept { return yuzu_; }
    ApState ap_state() const noexcept { return ap_; }
    SessionPhase session_phase() const noexcept { return phase_; }
    bool ap_established() const noexcept { return ap_ == ApState::Created; }
    const CitraAssociation& association() const noexcept { return assoc_; }
    bool connected() const noexcept;
    std::size_t client_count() const noexcept { return clients_.size(); }
    // V-016n rule 4.
    std::size_t node_count() const noexcept { return clients_.size() + 1; }
    // Client insertion order; SyncNetwork obligations follow it (rule 7 above).
    const std::vector<std::array<std::uint8_t, 4>>& clients() const noexcept { return clients_; }
    const std::vector<OutIntent>& outbox() const noexcept { return outbox_; }
    void clear_outbox() noexcept { outbox_.clear(); }

    // Self-check over the queued obligations: every LDN obligation is a body the
    // gateway may originate (ScanResp/SyncNetwork), carries this peer's fake IPv4
    // address when unicast and no address when broadcast; every Citra-frame
    // obligation is unicast exactly for AuthSeq2/AssocResponse and broadcast
    // exactly for NodeMap/Logoff.  Returns Err::Ok or the offending rule's error.
    Err validate_outbox() const noexcept;

    // --- LDN access point lifetime (V-016o rule 5) ---
    Err ap_initialized(Diag* diag = nullptr);
    Err ap_opened(Diag* diag = nullptr);
    Err ap_created(Diag* diag = nullptr);
    Err ap_destroyed(Diag* diag = nullptr);

    // --- Citra side (802.11 management, EAPoL, UDS data) ---
    Err citra_beacon_sent(Diag* diag = nullptr);
    // Handling the client's Authentication SEQ1: emits AuthSeq2 then
    // AssociationResponse, in that order, when the association is Successful.
    Err citra_auth_seq1(AssocOutcome outcome, Diag* diag = nullptr);
    // Handling the client's EAPoL-Start: emits NodeMap (broadcast) then EAPoL
    // Logoff (broadcast), in that order.
    Err citra_eapol_start(Diag* diag = nullptr);
    Err citra_eapol_logoff(Diag* diag = nullptr);
    Err citra_deauth(Diag* diag = nullptr);
    Err citra_data_in(Diag* diag = nullptr);
    Err citra_nodemap_in(Diag* diag = nullptr);

    // --- Yuzu side (LDN) ---
    Err yuzu_scan(const std::array<std::uint8_t, 4>& from_ip, Diag* diag = nullptr);
    Err yuzu_connect(const std::array<std::uint8_t, 4>& from_ip, Diag* diag = nullptr);
    Err yuzu_disconnect(const std::array<std::uint8_t, 4>& from_ip, Diag* diag = nullptr);
    Err yuzu_destroy_network(Diag* diag = nullptr);

    // Always refuses: the two wires never carry each other's native frames.
    Err guard_no_cross_side_leak(Side destination, Side origin, Diag* diag = nullptr);

private:
    Err illegal(const char* where, Diag* diag);
    Err transition(const char* where, Diag* diag);
    Err ap_step(const char* where, ApState from, ApState to, Diag* diag);
    void push(LdnPacketType type, bool broadcast, const std::array<std::uint8_t, 4>& ip);
    void push_citra(CitraFrameKind kind, bool broadcast);
    void sync_all_clients();

    CitraState citra_ = CitraState::Idle;
    YuzuState yuzu_ = YuzuState::Idle;
    ApState ap_ = ApState::Down;
    SessionPhase phase_ = SessionPhase::ApStandby;
    CitraAssociation assoc_{};
    std::vector<std::array<std::uint8_t, 4>> clients_;
    std::vector<OutIntent> outbox_;
};

} // namespace citra_control
