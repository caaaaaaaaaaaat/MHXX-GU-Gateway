// SPDX-License-Identifier: GPL-3.0-or-later
// citra-control - control-plane state machine.
#include "citra_control/state.hpp"

namespace citra_control {

namespace {

bool is_zero_ip(const std::array<std::uint8_t, 4>& ip) {
    return ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0;
}

// A broadcast Citra-side obligation must be exactly the two broadcast frames;
// everything else on that wire is unicast to the client being served.
bool citra_kind_is_broadcast(CitraFrameKind kind) {
    return kind == CitraFrameKind::NodeMap || kind == CitraFrameKind::Logoff;
}

} // namespace

const char* citra_state_name(CitraState state) noexcept {
    switch (state) {
    case CitraState::Idle: return "Idle";
    case CitraState::Beacon: return "Beacon";
    case CitraState::Authenticating: return "Authenticating";
    case CitraState::Associating: return "Associating";
    case CitraState::Connected: return "Connected";
    case CitraState::LoggedOff: return "LoggedOff";
    }
    return "Unknown";
}

const char* yuzu_state_name(YuzuState state) noexcept {
    switch (state) {
    case YuzuState::Idle: return "Idle";
    case YuzuState::Scanned: return "Scanned";
    case YuzuState::Connecting: return "Connecting";
    case YuzuState::Synced: return "Synced";
    case YuzuState::Connected: return "Connected";
    case YuzuState::Disconnected: return "Disconnected";
    }
    return "Unknown";
}

const char* ap_state_name(ApState state) noexcept {
    switch (state) {
    case ApState::Down: return "Down";
    case ApState::Initialized: return "Initialized";
    case ApState::Opened: return "Opened";
    case ApState::Created: return "Created";
    }
    return "Unknown";
}

const char* session_phase_name(SessionPhase phase) noexcept {
    switch (phase) {
    case SessionPhase::ApStandby: return "ApStandby";
    case SessionPhase::StationAdmitted: return "StationAdmitted";
    case SessionPhase::HallPresented: return "HallPresented";
    }
    return "Unknown";
}

const char* citra_frame_kind_name(CitraFrameKind kind) noexcept {
    switch (kind) {
    case CitraFrameKind::AuthSeq2: return "AuthSeq2";
    case CitraFrameKind::AssocResponse: return "AssocResponse";
    case CitraFrameKind::NodeMap: return "NodeMap";
    case CitraFrameKind::Logoff: return "Logoff";
    }
    return "Unknown";
}

Err validate_ldn_intent(const LdnIntent& intent, Diag* diag) {
    auto rej = [&](Err e) {
        if (diag != nullptr) {
            diag->note_reject("validate_ldn_intent", e);
        }
        return e;
    };
    if (intent.broadcast) {
        // SendBroadcast: no remote_ip at all.
        if (!is_zero_ip(intent.remote_ip)) {
            return rej(Err::BadSentinel);
        }
    } else {
        // SendPacket: remote_ip is always present (lan_discovery.cpp:421-476).
        if (is_zero_ip(intent.remote_ip)) {
            return rej(Err::BadSentinel);
        }
    }
    return Err::Ok;
}

void ControlPlane::reset(Diag* diag) noexcept {
    citra_ = CitraState::Idle;
    yuzu_ = YuzuState::Idle;
    ap_ = ApState::Down;
    phase_ = SessionPhase::ApStandby;
    assoc_.clear();
    clients_.clear();
    outbox_.clear();
    if (diag != nullptr) {
        diag->note_event("control_plane.reset", "reset");
    }
}

bool ControlPlane::connected() const noexcept {
    return citra_ == CitraState::Connected && yuzu_ == YuzuState::Connected && assoc_.complete();
}

Err ControlPlane::illegal(const char* where, Diag* diag) {
    if (diag != nullptr) {
        ++diag->c.state_illegal;
        diag->note_reject(where, Err::IllegalState);
    }
    return Err::IllegalState;
}

Err ControlPlane::transition(const char* where, Diag* diag) {
    if (diag != nullptr) {
        ++diag->c.state_transitions;
        diag->note_event(where, "transition");
    }
    return Err::Ok;
}

Err ControlPlane::ap_step(const char* where, ApState from, ApState to, Diag* diag) {
    if (ap_ != from) {
        return illegal(where, diag);
    }
    ap_ = to;
    if (diag != nullptr) {
        ++diag->c.ap_transitions;
    }
    return transition(where, diag);
}

void ControlPlane::push(LdnPacketType type, bool broadcast, const std::array<std::uint8_t, 4>& ip) {
    OutIntent intent;
    intent.side = Side::Yuzu;
    intent.ldn.type = type;
    intent.ldn.broadcast = broadcast;
    intent.ldn.remote_ip = broadcast ? std::array<std::uint8_t, 4>{} : ip;
    outbox_.push_back(intent);
}

void ControlPlane::push_citra(CitraFrameKind kind, bool broadcast) {
    OutIntent intent;
    intent.side = Side::Citra;
    intent.citra.kind = kind;
    intent.citra.broadcast = broadcast;
    outbox_.push_back(intent);
}

void ControlPlane::sync_all_clients() {
    // V-016n rule 2: one unicast SyncNetwork per connected client, including the
    // client that just connected (UpdateNodes iterates connected_clients), and in
    // clients_ insertion order for determinism (V-016o rule 7).
    for (const std::array<std::uint8_t, 4>& ip : clients_) {
        push(LdnPacketType::SyncNetwork, false, ip);
    }
}

Err ControlPlane::validate_outbox() const noexcept {
    for (const OutIntent& intent : outbox_) {
        if (intent.is_ldn()) {
            // The gateway originates only these two LDN bodies.
            if (intent.ldn.type != LdnPacketType::ScanResp &&
                intent.ldn.type != LdnPacketType::SyncNetwork) {
                return Err::Unsafe;
            }
            if (intent.ldn.broadcast) {
                if (!is_zero_ip(intent.ldn.remote_ip)) {
                    return Err::BadSentinel;
                }
            } else if (is_zero_ip(intent.ldn.remote_ip)) {
                return Err::BadSentinel;
            }
        } else {
            if (intent.citra.broadcast != citra_kind_is_broadcast(intent.citra.kind)) {
                return Err::Unsafe;
            }
        }
    }
    return Err::Ok;
}

// --- LDN access point lifetime (V-016o rule 5) ------------------------------

Err ControlPlane::ap_initialized(Diag* diag) {
    if (ap_ == ApState::Initialized) {
        return Err::Ok;  // idempotent reconfigure
    }
    return ap_step("ap_initialized", ApState::Down, ApState::Initialized, diag);
}

Err ControlPlane::ap_opened(Diag* diag) {
    if (ap_ == ApState::Opened) {
        return Err::Ok;
    }
    return ap_step("ap_opened", ApState::Initialized, ApState::Opened, diag);
}

Err ControlPlane::ap_created(Diag* diag) {
    if (ap_ == ApState::Created) {
        return Err::Ok;
    }
    return ap_step("ap_created", ApState::Opened, ApState::Created, diag);
}

Err ControlPlane::ap_destroyed(Diag* diag) {
    if (ap_ == ApState::Down) {
        return illegal("ap_destroyed", diag);
    }
    ap_ = ApState::Down;
    if (diag != nullptr) {
        ++diag->c.ap_transitions;
    }
    return transition("ap_destroyed", diag);
}

// --- Citra side -------------------------------------------------------------

Err ControlPlane::citra_beacon_sent(Diag* diag) {
    // Advertising the host network is independent of the served client's
    // association phase. A timer tick must never reset an in-flight handshake
    // or an established connection back to Beacon (D6).
    if (citra_ == CitraState::Associating || citra_ == CitraState::Connected) {
        return transition("citra_beacon_sent", diag);
    }
    if (citra_ != CitraState::Idle && citra_ != CitraState::Beacon && citra_ != CitraState::LoggedOff) {
        return illegal("citra_beacon_sent", diag);
    }
    citra_ = CitraState::Beacon;
    return transition("citra_beacon_sent", diag);
}

Err ControlPlane::citra_auth_seq1(AssocOutcome outcome, Diag* diag) {
    if (citra_ != CitraState::Beacon && citra_ != CitraState::Authenticating) {
        return illegal("citra_auth_seq1", diag);
    }
    assoc_ = CitraAssociation{};
    if (outcome != AssocOutcome::Successful) {
        // V-016k: never serve a refused association with frames, and never enter
        // Associating; a real Citra client asserts on a non-successful result.
        if (diag != nullptr) {
            ++diag->c.unsafe_assoc_blocked;
            diag->note_reject("citra_auth_seq1", Err::Unsafe);
        }
        return Err::Unsafe;
    }
    // The gateway answers Authentication SEQ1 with SEQ2 and then the
    // AssociationResponse: fixed order, both unicast to the served client.
    assoc_.auth_seq1 = true;
    assoc_.auth_seq2 = true;
    assoc_.assoc_response = true;
    citra_ = CitraState::Associating;
    push_citra(CitraFrameKind::AuthSeq2, false);
    push_citra(CitraFrameKind::AssocResponse, false);
    return transition("citra_auth_seq1", diag);
}

Err ControlPlane::citra_eapol_start(Diag* diag) {
    if (citra_ != CitraState::Associating || !assoc_.auth_seq1 || !assoc_.auth_seq2 ||
        !assoc_.assoc_response) {
        return illegal("citra_eapol_start", diag);
    }
    assoc_.eapol_start = true;
    citra_ = CitraState::Connected;
    // A client that has just been assigned a node id makes the host broadcast the
    // refreshed node map and the EAPoL Logoff carrying the node list.
    push_citra(CitraFrameKind::NodeMap, true);
    push_citra(CitraFrameKind::Logoff, true);
    return transition("citra_eapol_start", diag);
}

Err ControlPlane::citra_eapol_logoff(Diag* diag) {
    if (citra_ == CitraState::Idle) {
        return illegal("citra_eapol_logoff", diag);
    }
    assoc_.clear();
    citra_ = CitraState::LoggedOff;
    return transition("citra_eapol_logoff", diag);
}

Err ControlPlane::citra_deauth(Diag* diag) {
    if (citra_ == CitraState::Idle) {
        return illegal("citra_deauth", diag);
    }
    assoc_.clear();
    citra_ = CitraState::LoggedOff;
    return transition("citra_deauth", diag);
}

Err ControlPlane::citra_data_in(Diag* diag) {
    if (citra_ != CitraState::Connected) {
        return illegal("citra_data_in", diag);
    }
    return Err::Ok;
}

Err ControlPlane::citra_nodemap_in(Diag* diag) {
    if (citra_ != CitraState::Connected) {
        return illegal("citra_nodemap_in", diag);
    }
    return Err::Ok;
}

// --- Yuzu side --------------------------------------------------------------

Err ControlPlane::yuzu_scan(const std::array<std::uint8_t, 4>& from_ip, Diag* diag) {
    if (is_zero_ip(from_ip)) {
        if (diag != nullptr) {
            diag->note_reject("yuzu_scan", Err::BadSentinel);
        }
        return Err::BadSentinel;
    }
    if (!ap_established()) {
        // V-016o rule 5: no AP, no advertisement.  Refused and counted instead of
        // silently answering the scan.
        if (diag != nullptr) {
            ++diag->c.scan_resp_no_ap;
            diag->note_reject("yuzu_scan", Err::IllegalState, "ap is not Created");
        }
        return Err::IllegalState;
    }
    // The access point answers a Scan with a unicast ScanResp.
    push(LdnPacketType::ScanResp, false, from_ip);
    if (yuzu_ == YuzuState::Idle || yuzu_ == YuzuState::Disconnected) {
        yuzu_ = YuzuState::Scanned;
    }
    return transition("yuzu_scan", diag);
}

Err ControlPlane::yuzu_connect(const std::array<std::uint8_t, 4>& from_ip, Diag* diag) {
    if (is_zero_ip(from_ip)) {
        if (diag != nullptr) {
            diag->note_reject("yuzu_connect", Err::BadSentinel);
        }
        return Err::BadSentinel;
    }
    if (!ap_established()) {
        if (diag != nullptr) {
            ++diag->c.connect_no_ap;
            diag->note_reject("yuzu_connect", Err::IllegalState, "ap is not Created");
        }
        return Err::IllegalState;
    }
    for (const std::array<std::uint8_t, 4>& ip : clients_) {
        if (ip == from_ip) {
            return illegal("yuzu_connect", diag);
        }
    }
    clients_.push_back(from_ip);
    yuzu_ = YuzuState::Connecting;
    sync_all_clients();
    yuzu_ = YuzuState::Connected;
    // V-243: passive session-phase advance (recorded, never branched on).
    if (phase_ == SessionPhase::ApStandby) {
        phase_ = SessionPhase::StationAdmitted;
        if (diag != nullptr) {
            diag->note_event("session_phase", session_phase_name(phase_));
        }
    }
    return transition("yuzu_connect", diag);
}

Err ControlPlane::yuzu_disconnect(const std::array<std::uint8_t, 4>& from_ip, Diag* diag) {
    for (std::size_t i = 0; i < clients_.size(); ++i) {
        if (clients_[i] == from_ip) {
            clients_.erase(clients_.begin() + static_cast<std::ptrdiff_t>(i));
            sync_all_clients();
            if (clients_.empty()) {
                yuzu_ = YuzuState::Disconnected;
                // V-243: the hall dissolved with its last guest.
                phase_ = SessionPhase::ApStandby;
            }
            return transition("yuzu_disconnect", diag);
        }
    }
    if (diag != nullptr) {
        diag->note_reject("yuzu_disconnect", Err::NotFound);
    }
    return Err::NotFound;
}

Err ControlPlane::yuzu_destroy_network(Diag* diag) {
    // Host leaves: clients just stop receiving SyncNetwork, no Disconnect body,
    // and the AP the gateway was advertising is torn down with it.
    clients_.clear();
    ap_ = ApState::Down;
    yuzu_ = YuzuState::Disconnected;
    phase_ = SessionPhase::ApStandby;
    return transition("yuzu_destroy_network", diag);
}

Err ControlPlane::guard_no_cross_side_leak(Side destination, Side origin, Diag* diag) {
    (void)destination;
    (void)origin;
    if (diag != nullptr) {
        ++diag->c.cross_side_leak_blocked;
        diag->note_reject("guard_no_cross_side_leak", Err::Unsafe);
    }
    return Err::Unsafe;
}

} // namespace citra_control
