// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
// Shared test-case helpers plus one entry point per protocol case.
#include "harness.hpp"

#include <citra_room/protocol.hpp>
#include <room_client/protocol.hpp>

#include <functional>

namespace rri {

CaseResult begin_case(const RunConfig& cfg, const ServerSpec& spec, const std::string& id);
void end_case(CaseResult& result, std::uint64_t t0_ms);

// --- frozen-codec generated inputs and expected outputs -------------------------------
room_client::Bytes v1_join_bytes(const std::string& nickname,
                                 const room_client::IPv4& preferred_ip,
                                 const std::string& password, std::uint32_t version);
room_client::Bytes v1_expected_error(room_client::MessageId id, std::uint32_t server_version = 0);
citra_room::Bytes v4_join_bytes(const std::string& nickname, const std::string& console_id_hash,
                                const citra_room::MacAddress& preferred_mac,
                                const std::string& password, std::uint32_t version);
citra_room::Bytes v4_expected_error(citra_room::MessageId id, std::uint32_t server_version = 0);

// --- decode/observation helpers -------------------------------------------------------
bool decode_v1_s2c(const Bytes& bytes, room_client::Message& out, std::string& error);
bool decode_v4_s2c(const Bytes& bytes, citra_room::Message& out, std::string& error);
std::string v1_name(const room_client::Message& message);
std::string v4_name(const citra_room::Message& message);
bool frame_is_join_success(const Bytes& frame);

std::vector<Bytes> wait_server_frames_until(
    RawClient& client, const std::function<bool(const std::vector<Bytes>&)>& predicate,
    std::uint64_t timeout_ms);
std::vector<Bytes> wait_server_frames(RawClient& client, std::size_t min_count,
                                      std::uint64_t timeout_ms);
void expect_single_error_frame(CaseResult& result, RawClient& client, const Bytes& expected,
                               const std::string& label);
void check_v1_server_error(CaseResult& result, const Bytes& frame, room_client::MessageId id,
                           std::uint32_t server_version, const std::string& label);
void check_v4_server_error(CaseResult& result, const Bytes& frame, citra_room::MessageId id,
                           std::uint32_t server_version, const std::string& label);

int v1_find(const std::vector<Bytes>& frames, room_client::MessageId id);
int v4_find(const std::vector<Bytes>& frames, citra_room::MessageId id);
bool v1_room_info(const std::vector<Bytes>& frames, room_client::RoomInformation& out);
bool v1_join_success(const std::vector<Bytes>& frames, room_client::JoinSuccess& out);
bool v4_room_info(const std::vector<Bytes>& frames, citra_room::RoomInformation& out);
bool v4_join_success(const std::vector<Bytes>& frames, citra_room::JoinSuccess& out);
bool v1_member_named(const room_client::RoomInformation& info, const std::string& nickname);
bool v4_member_named(const citra_room::RoomInformation& info, const std::string& nickname);

bool v1_join_and_wait(RawClient& client, const std::string& nickname, const std::string& password,
                      std::uint16_t port, CaseResult& result, const std::string& role,
                      room_client::IPv4& out_ip);
bool v4_join_and_wait(RawClient& client, const std::string& nickname, const std::string& console_id,
                      const std::string& password, std::uint16_t port, CaseResult& result,
                      const std::string& role, citra_room::MacAddress& out_mac);

// --- v1 (yuzu / original-source) cases ------------------------------------------------
CaseResult case_join(const RunConfig&, const ServerSpec&);
CaseResult case_version_mismatch(const RunConfig&, const ServerSpec&);
CaseResult case_wrong_password(const RunConfig&, const ServerSpec&);
CaseResult case_name_collision(const RunConfig&, const ServerSpec&);
CaseResult case_ip_collision(const RunConfig&, const ServerSpec&);
CaseResult case_room_full(const RunConfig&, const ServerSpec&);
CaseResult case_release(const RunConfig&, const ServerSpec&);
CaseResult case_m2_parity(const RunConfig&, const ServerSpec&);
CaseResult case_port_conflict(const RunConfig&, const ServerSpec&);
CaseResult case_family_isolation(const RunConfig&, const ServerSpec&);
CaseResult case_proxy_route(const RunConfig&, const ServerSpec&);
CaseResult case_proxy_broadcast(const RunConfig&, const ServerSpec&);
CaseResult case_dataplane_size(const RunConfig&, const ServerSpec&);
CaseResult case_chat_limit(const RunConfig&, const ServerSpec&);
CaseResult case_unjoined_source(const RunConfig&, const ServerSpec&);
CaseResult case_error_order(const RunConfig&, const ServerSpec&);
CaseResult case_fixture_bytes(const RunConfig&, const ServerSpec&);

// --- v4 (citra) cases -----------------------------------------------------------------
CaseResult case_join_v4(const RunConfig&, const ServerSpec&);
CaseResult case_version_mismatch_v4(const RunConfig&, const ServerSpec&);
CaseResult case_wrong_password_v4(const RunConfig&, const ServerSpec&);
CaseResult case_name_collision_v4(const RunConfig&, const ServerSpec&);
CaseResult case_room_full_v4(const RunConfig&, const ServerSpec&);
CaseResult case_chat_v4(const RunConfig&, const ServerSpec&);
CaseResult case_wifi_route_v4(const RunConfig&, const ServerSpec&);
CaseResult case_wifi_broadcast_v4(const RunConfig&, const ServerSpec&);
CaseResult case_console_id_collision_v4(const RunConfig&, const ServerSpec&);
CaseResult case_error_order_v4(const RunConfig&, const ServerSpec&);

} // namespace rri
