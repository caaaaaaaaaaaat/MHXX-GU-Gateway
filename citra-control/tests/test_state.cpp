// SPDX-License-Identifier: GPL-3.0-or-later
// citra-control - control-plane state machine tests (docs/M4-CONTROL-PLANE.md
// section 4; V-016k cross-side leak rule; V-016n rules 1/2/4; V-016o rules
// 5/6/7: AP gate, ordered emission obligations, deterministic SyncNetwork order).
#include <string>

#include "citra_control/state.hpp"
#include "util.hpp"

using namespace citra_control;

namespace {

const std::array<std::uint8_t, 4> kIpA{10, 83, 0, 1};
const std::array<std::uint8_t, 4> kIpB{10, 83, 0, 2};
const std::array<std::uint8_t, 4> kIpZero{0, 0, 0, 0};

LdnIntent intent_of(LdnPacketType type, bool broadcast, const std::array<std::uint8_t, 4>& ip) {
    LdnIntent i;
    i.type = type;
    i.broadcast = broadcast;
    i.remote_ip = ip;
    return i;
}

// Bring a plane into the intended deployment state: LDN AP created.
void bring_ap_up(ControlPlane& cp, Diag& d) {
    cp.ap_initialized(&d);
    cp.ap_opened(&d);
    cp.ap_created(&d);
}

} // namespace

// ---------------------------------------------------------------------------
// V-016o rule 5: the AP-established gate in front of ScanResp and Connect.
// ---------------------------------------------------------------------------
TT_SUITE(state_ap) {
    TT_CASE();
    {
        ControlPlane cp;
        Diag d;
        d.events_enabled = false;

        TT_CHECK(cp.ap_state() == ApState::Down);
        TT_CHECK(!cp.ap_established());

        // No AP: a Scan is refused and counted, nothing is queued.
        TT_CHECK(cp.yuzu_scan(kIpA, &d) == Err::IllegalState);
        TT_CHECK(d.c.scan_resp_no_ap == 1);
        TT_CHECK(cp.outbox().empty());
        TT_CHECK(cp.yuzu_state() == YuzuState::Idle);

        // No AP: a Connect is refused and counted too.
        TT_CHECK(cp.yuzu_connect(kIpA, &d) == Err::IllegalState);
        TT_CHECK(d.c.connect_no_ap == 1);
        TT_CHECK(cp.client_count() == 0);
        TT_CHECK(cp.outbox().empty());

        // Lifecycle ordering is enforced.
        TT_CHECK(cp.ap_created(&d) == Err::IllegalState);   // needs Opened first
        TT_CHECK(cp.ap_opened(&d) == Err::IllegalState);    // needs Initialized first
        TT_CHECK(cp.ap_destroyed(&d) == Err::IllegalState); // already Down
        TT_CHECK(cp.ap_state() == ApState::Down);
        TT_CHECK(d.c.state_illegal == 3);

        TT_CHECK(cp.ap_initialized(&d) == Err::Ok);
        TT_CHECK(cp.ap_state() == ApState::Initialized);
        TT_CHECK(cp.ap_initialized(&d) == Err::Ok); // idempotent
        TT_CHECK(cp.ap_opened(&d) == Err::Ok);
        TT_CHECK(cp.ap_state() == ApState::Opened);
        TT_CHECK(!cp.ap_established()); // Opened alone does not advertise
        TT_CHECK(cp.ap_created(&d) == Err::Ok);
        TT_CHECK(cp.ap_established());
        TT_CHECK(cp.ap_created(&d) == Err::Ok);     // idempotent
        TT_CHECK(cp.ap_state() == ApState::Created);
        TT_CHECK(d.c.ap_transitions == 3);
        TT_CHECK(std::string(ap_state_name(cp.ap_state())) == "Created");
    }

    TT_CASE();
    {
        ControlPlane cp;
        Diag d;
        d.events_enabled = false;
        bring_ap_up(cp, d);
        TT_CHECK(cp.ap_established());

        // AP established: exactly one unicast ScanResp to the initiator.
        TT_CHECK(cp.yuzu_scan(kIpA, &d) == Err::Ok);
        TT_CHECK(cp.yuzu_state() == YuzuState::Scanned);
        TT_CHECK(cp.outbox().size() == 1);
        if (cp.outbox().size() == 1) {
            const OutIntent& o = cp.outbox()[0];
            TT_CHECK(o.is_ldn());
            TT_CHECK(o.ldn.type == LdnPacketType::ScanResp);
            TT_CHECK(!o.ldn.broadcast);
            TT_CHECK(o.ldn.remote_ip == kIpA);
            TT_CHECK(validate_ldn_intent(o.ldn, &d) == Err::Ok);
        }
        TT_CHECK(cp.validate_outbox() == Err::Ok);

        // A second scanner gets its own single ScanResp.
        cp.clear_outbox();
        TT_CHECK(cp.yuzu_scan(kIpB, &d) == Err::Ok);
        TT_CHECK(cp.outbox().size() == 1);
        TT_CHECK(cp.outbox()[0].ldn.remote_ip == kIpB);

        // Tearing the AP down closes the gate again.
        TT_CHECK(cp.ap_destroyed(&d) == Err::Ok);
        TT_CHECK(cp.ap_state() == ApState::Down);
        TT_CHECK(!cp.ap_established());
        cp.clear_outbox();
        TT_CHECK(cp.yuzu_scan(kIpA, &d) == Err::IllegalState);
        TT_CHECK(cp.outbox().empty());
        TT_CHECK(d.c.scan_resp_no_ap == 1);
    }
}

// ---------------------------------------------------------------------------
// Citra side: folded association and the ordered frame obligations (rule 6).
// ---------------------------------------------------------------------------
TT_SUITE(state_citra) {
    TT_CASE();
    {
        ControlPlane cp;
        Diag d;
        d.events_enabled = false;
        TT_CHECK(cp.citra_state() == CitraState::Idle);
        TT_CHECK(!cp.connected());
        TT_CHECK(!cp.association().complete());

        // Data before the association completes is refused.
        TT_CHECK(cp.citra_data_in(&d) == Err::IllegalState);
        // Authentication SEQ1 before any Beacon is refused.
        TT_CHECK(cp.citra_auth_seq1(AssocOutcome::Successful, &d) == Err::IllegalState);
        // EAPoL-Start before the association is refused.
        TT_CHECK(cp.citra_eapol_start(&d) == Err::IllegalState);
        TT_CHECK(cp.citra_state() == CitraState::Idle);
        TT_CHECK(cp.outbox().empty());
        TT_CHECK(d.c.state_illegal == 3);

        TT_CHECK(cp.citra_beacon_sent(&d) == Err::Ok);
        TT_CHECK(cp.citra_state() == CitraState::Beacon);
        // The Beacon itself is the caller's frame, not a queued obligation.
        TT_CHECK(cp.outbox().empty());
        TT_CHECK(cp.citra_eapol_start(&d) == Err::IllegalState);
        TT_CHECK(!cp.connected());

        // SEQ1 yields SEQ2 and then the AssociationResponse, in that order.
        TT_CHECK(cp.citra_auth_seq1(AssocOutcome::Successful, &d) == Err::Ok);
        TT_CHECK(cp.citra_state() == CitraState::Associating);
        TT_CHECK(cp.association().auth_seq1);
        TT_CHECK(cp.association().auth_seq2);
        TT_CHECK(cp.association().assoc_response);
        TT_CHECK(!cp.association().complete());
        TT_CHECK(cp.outbox().size() == 2);
        if (cp.outbox().size() == 2) {
            TT_CHECK(cp.outbox()[0].is_citra());
            TT_CHECK(cp.outbox()[0].citra.kind == CitraFrameKind::AuthSeq2);
            TT_CHECK(!cp.outbox()[0].citra.broadcast);
            TT_CHECK(cp.outbox()[1].is_citra());
            TT_CHECK(cp.outbox()[1].citra.kind == CitraFrameKind::AssocResponse);
            TT_CHECK(!cp.outbox()[1].citra.broadcast);
        }
        TT_CHECK(cp.validate_outbox() == Err::Ok);
        TT_CHECK(cp.citra_data_in(&d) == Err::IllegalState);

        // EAPoL-Start yields the broadcast NodeMap and then the broadcast Logoff.
        TT_CHECK(cp.citra_beacon_sent(&d) == Err::Ok);
        TT_CHECK(cp.citra_state() == CitraState::Associating);
        TT_CHECK(cp.association().auth_seq1 && cp.association().auth_seq2 &&
                 cp.association().assoc_response && !cp.association().eapol_start);
        TT_CHECK(cp.outbox().size() == 2);
        cp.clear_outbox();
        TT_CHECK(cp.citra_eapol_start(&d) == Err::Ok);
        TT_CHECK(cp.citra_state() == CitraState::Connected);
        TT_CHECK(cp.association().complete());
        TT_CHECK(cp.outbox().size() == 2);
        if (cp.outbox().size() == 2) {
            TT_CHECK(cp.outbox()[0].citra.kind == CitraFrameKind::NodeMap);
            TT_CHECK(cp.outbox()[0].citra.broadcast);
            TT_CHECK(cp.outbox()[1].citra.kind == CitraFrameKind::Logoff);
            TT_CHECK(cp.outbox()[1].citra.broadcast);
        }
        TT_CHECK(cp.validate_outbox() == Err::Ok);

        for (int tick = 0; tick < 3; ++tick) {
            TT_CHECK(cp.citra_beacon_sent(&d) == Err::Ok);
            TT_CHECK(cp.citra_state() == CitraState::Connected);
            TT_CHECK(cp.association().complete());
            TT_CHECK(cp.outbox().size() == 2);
        }
        TT_CHECK(cp.citra_data_in(&d) == Err::Ok);
        TT_CHECK(cp.citra_nodemap_in(&d) == Err::Ok);

        // Re-authenticating while Connected is not part of the folded model: it
        // is refused, counted, and leaves both state and outbox untouched.
        cp.clear_outbox();
        TT_CHECK(cp.citra_auth_seq1(AssocOutcome::Successful, &d) == Err::IllegalState);
        TT_CHECK(cp.association().complete());
        TT_CHECK(cp.citra_state() == CitraState::Connected);
        TT_CHECK(cp.outbox().empty());
        TT_CHECK(d.c.state_illegal == 6);
    }

    TT_CASE();
    {
        ControlPlane cp;
        Diag d;
        d.events_enabled = false;
        cp.citra_beacon_sent(&d);
        cp.clear_outbox();

        // V-016k: a refused association produces NO frame obligation at all and
        // never enters Associating.
        TT_CHECK(cp.citra_auth_seq1(AssocOutcome::Refused, &d) == Err::Unsafe);
        TT_CHECK(d.c.unsafe_assoc_blocked == 1);
        TT_CHECK(cp.outbox().empty());
        TT_CHECK(cp.citra_state() == CitraState::Beacon);
        TT_CHECK(!cp.association().auth_seq1);
        TT_CHECK(!cp.association().auth_seq2);
        TT_CHECK(!cp.association().assoc_response);
        TT_CHECK(cp.citra_data_in(&d) == Err::IllegalState);

        // A successful retry afterwards behaves normally.
        TT_CHECK(cp.citra_auth_seq1(AssocOutcome::Successful, &d) == Err::Ok);
        TT_CHECK(cp.outbox().size() == 2);
        cp.clear_outbox();
        TT_CHECK(cp.citra_eapol_start(&d) == Err::Ok);
        TT_CHECK(cp.citra_state() == CitraState::Connected);
        cp.clear_outbox();

        // EAPoL-Logoff ends the session: no obligations, no more data.
        TT_CHECK(cp.citra_eapol_logoff(&d) == Err::Ok);
        TT_CHECK(cp.citra_state() == CitraState::LoggedOff);
        TT_CHECK(!cp.association().complete());
        TT_CHECK(cp.outbox().empty());
        TT_CHECK(cp.citra_data_in(&d) == Err::IllegalState);
        TT_CHECK(cp.citra_nodemap_in(&d) == Err::IllegalState);

        // Re-associating is allowed again from LoggedOff.
        TT_CHECK(cp.citra_beacon_sent(&d) == Err::Ok);
        TT_CHECK(cp.citra_state() == CitraState::Beacon);
        TT_CHECK(cp.citra_auth_seq1(AssocOutcome::Successful, &d) == Err::Ok);
        TT_CHECK(cp.outbox().size() == 2);
        cp.clear_outbox();

        // Deauthentication also ends the session and drops the association.
        TT_CHECK(cp.citra_deauth(&d) == Err::Ok);
        TT_CHECK(cp.citra_state() == CitraState::LoggedOff);
        TT_CHECK(!cp.association().auth_seq1);
        TT_CHECK(cp.outbox().empty());
    }
}

// ---------------------------------------------------------------------------
// Yuzu side: transfer forms (V-016n rule 1), node count (rule 4),
// SyncNetwork-on-change (rule 2) and deterministic order (V-016o rule 7).
// ---------------------------------------------------------------------------
TT_SUITE(state_yuzu) {
    TT_CASE();
    {
        ControlPlane cp;
        Diag d;
        d.events_enabled = false;
        bring_ap_up(cp, d);

        TT_CHECK(cp.yuzu_scan(kIpA, &d) == Err::Ok);
        TT_CHECK(cp.yuzu_state() == YuzuState::Scanned);
        TT_CHECK(cp.outbox().size() == 1);
        TT_CHECK(cp.outbox()[0].is_ldn());
        TT_CHECK(cp.outbox()[0].ldn.type == LdnPacketType::ScanResp);
        TT_CHECK(cp.outbox()[0].ldn.remote_ip == kIpA);

        // A zero source address is refused (fail-closed), before the AP gate.
        TT_CHECK(cp.yuzu_scan(kIpZero, &d) == Err::BadSentinel);

        cp.clear_outbox();
        TT_CHECK(cp.yuzu_connect(kIpA, &d) == Err::Ok);
        TT_CHECK(cp.client_count() == 1);
        TT_CHECK(cp.node_count() == 2); // V-016n rule 4
        TT_CHECK(cp.outbox().size() == 1);
        if (cp.outbox().size() == 1) {
            TT_CHECK(cp.outbox()[0].ldn.type == LdnPacketType::SyncNetwork);
            TT_CHECK(cp.outbox()[0].ldn.remote_ip == kIpA);
        }
        TT_CHECK(cp.validate_outbox() == Err::Ok);

        // V-016n rule 2 + V-016o rule 7: every Connect pushes one unicast
        // SyncNetwork per connected client, in insertion order, new client last.
        cp.clear_outbox();
        TT_CHECK(cp.yuzu_connect(kIpB, &d) == Err::Ok);
        TT_CHECK(cp.client_count() == 2);
        TT_CHECK(cp.node_count() == 3);
        TT_CHECK(cp.outbox().size() == 2);
        if (cp.outbox().size() == 2) {
            TT_CHECK(cp.outbox()[0].is_ldn());
            TT_CHECK(cp.outbox()[0].ldn.type == LdnPacketType::SyncNetwork);
            TT_CHECK(cp.outbox()[0].ldn.remote_ip == kIpA); // clients_[0]
            TT_CHECK(cp.outbox()[1].ldn.type == LdnPacketType::SyncNetwork);
            TT_CHECK(cp.outbox()[1].ldn.remote_ip == kIpB); // clients_[1], the new one
        }
        TT_CHECK(cp.clients().size() == 2);
        TT_CHECK(cp.clients()[0] == kIpA);
        TT_CHECK(cp.clients()[1] == kIpB);
        TT_CHECK(cp.validate_outbox() == Err::Ok);
        for (const OutIntent& o : cp.outbox()) {
            TT_CHECK(o.is_ldn() != o.is_citra());
            if (o.is_ldn()) {
                TT_CHECK(validate_ldn_intent(o.ldn, &d) == Err::Ok);
                TT_CHECK(!(o.ldn.remote_ip == kIpZero));
            }
        }

        // Duplicate Connect is refused.
        TT_CHECK(cp.yuzu_connect(kIpA, &d) == Err::IllegalState);

        // Disconnect pushes SyncNetwork to the remaining clients only.
        cp.clear_outbox();
        TT_CHECK(cp.yuzu_disconnect(kIpA, &d) == Err::Ok);
        TT_CHECK(cp.client_count() == 1);
        TT_CHECK(cp.node_count() == 2);
        TT_CHECK(cp.outbox().size() == 1);
        if (cp.outbox().size() == 1) {
            TT_CHECK(cp.outbox()[0].ldn.type == LdnPacketType::SyncNetwork);
            TT_CHECK(cp.outbox()[0].ldn.remote_ip == kIpB);
        }
        TT_CHECK(cp.yuzu_disconnect(kIpA, &d) == Err::NotFound);
        TT_CHECK(cp.yuzu_scan(kIpA, &d) == Err::Ok); // discovery still works

        // DestroyNetwork empties the table, emits nothing, and tears the AP down.
        cp.clear_outbox();
        TT_CHECK(cp.yuzu_destroy_network(&d) == Err::Ok);
        TT_CHECK(cp.client_count() == 0);
        TT_CHECK(cp.node_count() == 1);
        TT_CHECK(cp.outbox().empty());
        TT_CHECK(cp.yuzu_state() == YuzuState::Disconnected);
        TT_CHECK(cp.ap_state() == ApState::Down);
        TT_CHECK(cp.yuzu_connect(kIpA, &d) == Err::IllegalState);
        TT_CHECK(d.c.connect_no_ap == 1);
    }

    TT_CASE();
    {
        // V-016n rule 1: exactly one of the two send forms is legal.
        Diag d;
        d.events_enabled = false;
        TT_CHECK(validate_ldn_intent(intent_of(LdnPacketType::Scan, true, kIpZero), &d) == Err::Ok);
        TT_CHECK(validate_ldn_intent(intent_of(LdnPacketType::ScanResp, false, kIpA), &d) == Err::Ok);
        TT_CHECK(validate_ldn_intent(intent_of(LdnPacketType::SyncNetwork, false, kIpA), &d) == Err::Ok);
        TT_CHECK(validate_ldn_intent(intent_of(LdnPacketType::DestroyNetwork, true, kIpA), &d) == Err::BadSentinel);
        TT_CHECK(validate_ldn_intent(intent_of(LdnPacketType::Connect, false, kIpZero), &d) == Err::BadSentinel);
        TT_CHECK(d.c.decode_reject == 2);

        // Every obligation produced across a whole session passes both checks.
        ControlPlane cp;
        bring_ap_up(cp, d);
        cp.yuzu_scan(kIpA, &d);
        cp.yuzu_connect(kIpA, &d);
        cp.yuzu_scan(kIpB, &d);
        cp.yuzu_connect(kIpB, &d);
        cp.yuzu_disconnect(kIpA, &d);
        TT_CHECK(cp.validate_outbox() == Err::Ok);
        for (const OutIntent& o : cp.outbox()) {
            if (o.is_ldn()) {
                TT_CHECK(validate_ldn_intent(o.ldn, &d) == Err::Ok);
                if (!o.ldn.broadcast) {
                    TT_CHECK(!(o.ldn.remote_ip == kIpZero));
                }
            }
        }
        TT_CHECK(std::string(citra_frame_kind_name(CitraFrameKind::NodeMap)) == "NodeMap");
    }
}

// ---------------------------------------------------------------------------
// Folding and reachability.
// ---------------------------------------------------------------------------
TT_SUITE(state_fold) {
    TT_CASE();
    {
        ControlPlane cp;
        Diag d;
        d.events_enabled = false;
        bring_ap_up(cp, d);

        // The folded Citra handshake produces Citra-side obligations only; no LDN
        // body is ever produced for it.
        cp.citra_beacon_sent(&d);
        TT_CHECK(cp.outbox().empty());
        cp.citra_auth_seq1(AssocOutcome::Successful, &d);
        cp.citra_eapol_start(&d);
        TT_CHECK(cp.outbox().size() == 4);
        for (const OutIntent& o : cp.outbox()) {
            TT_CHECK(o.is_citra());
        }

        // Yuzu-side events produce LDN obligations only.
        cp.clear_outbox();
        TT_CHECK(cp.yuzu_scan(kIpA, &d) == Err::Ok);
        TT_CHECK(cp.yuzu_connect(kIpA, &d) == Err::Ok);
        TT_CHECK(cp.outbox().size() == 2);
        for (const OutIntent& o : cp.outbox()) {
            TT_CHECK(o.is_ldn());
        }
        TT_CHECK(cp.connected());

        // The library never forwards one wire's native frame to the other.
        TT_CHECK(cp.guard_no_cross_side_leak(Side::Citra, Side::Yuzu, &d) == Err::Unsafe);
        TT_CHECK(cp.guard_no_cross_side_leak(Side::Yuzu, Side::Citra, &d) == Err::Unsafe);
        TT_CHECK(cp.guard_no_cross_side_leak(Side::Citra, Side::Citra, &d) == Err::Unsafe);
        TT_CHECK(d.c.cross_side_leak_blocked == 3);

        // Losing the Citra side breaks the folded Connected state.
        cp.citra_eapol_logoff(&d);
        TT_CHECK(!cp.connected());

        cp.reset(&d);
        TT_CHECK(cp.citra_state() == CitraState::Idle);
        TT_CHECK(cp.yuzu_state() == YuzuState::Idle);
        TT_CHECK(cp.ap_state() == ApState::Down);
        TT_CHECK(cp.client_count() == 0);
        TT_CHECK(cp.outbox().empty());
        TT_CHECK(!cp.association().auth_seq1);
    }

    TT_CASE();
    {
        // Reachability: Connected requires both sides plus a complete association.
        ControlPlane cp;
        Diag d;
        d.events_enabled = false;
        bring_ap_up(cp, d);
        cp.yuzu_scan(kIpA, &d);
        cp.yuzu_connect(kIpA, &d);
        for (int i = 0; i < 3; ++i) {
            cp.citra_beacon_sent(&d);
            cp.citra_auth_seq1(AssocOutcome::Successful, &d);
            TT_CHECK(!cp.connected()); // association incomplete (no EAPoL-Start)
            cp.citra_eapol_start(&d);
            TT_CHECK(cp.connected());
            cp.citra_eapol_logoff(&d);
            TT_CHECK(!cp.connected());
        }
        TT_CHECK(cp.client_count() == 1);
        TT_CHECK(std::string(citra_state_name(cp.citra_state())) == "LoggedOff");
        TT_CHECK(std::string(yuzu_state_name(cp.yuzu_state())) == "Connected");
    }
}
