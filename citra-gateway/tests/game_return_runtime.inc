// Synthetic loopback regression for V-273's actual failure: a real room peer
// has no Citra-session identity, but an admitted/injected station has a UDS id.
void group_b17_game_return_runtime() {
    RoomGuard room(take_port(), 4);
    auto options = gateway_options(take_port(), room);
    options.control_plane_enabled = true;
    options.ldn_guest_inject = true;
    options.ldn_announce_forward = true;
    options.ldn_game_return = true;
    options.proxy_udp_port = 12345;
    const std::array<std::uint8_t, 4> xx{0xb3, 0x5e, 0xe2, 0x7f};
    const std::array<std::uint8_t, 4> gu{192, 168, 1, 1};
    options.ldn_identity_pairs.push_back({xx, gu});
    citra_gateway::Gateway gateway(options);
    gateway.open();
    RawRoomPeer yuzu(room.port(), "return-yuzu", room_client::network_version,
                     room_client::IPv4{10, 83, 2, 10});
    const auto ip = wait_assigned_ip(yuzu);
    verify(ip.has_value(), "B17 Yuzu room peer joins without a Citra session mapping");
    CitraPeer alpha;
    alpha.connect(gateway.port());
    verify(join_peer(gateway, alpha, "return-host", "return-console"), "B17 host joins gateway");
    verify(drive(gateway, {&alpha}, [&] { return gateway.counters().members_in_room == 2; }, 2000),
           "B17 room membership is visible");
    const auto id = client_id_for(gateway, "return-host");
    const auto mac = alpha.assigned_mac();
    verify(mac.has_value(), "B17 host MAC assigned");
    const auto host_identity = identity_for(gateway, "return-host");
    verify(host_identity && host_identity->fake_ip == gu,
           "B17 the explicit host identity pair matches its assigned room endpoint");
    const citra_room::MacAddress station_mac{2, 0, 10, 83, 2, 10};
    auto inject_wifi = [&](citra_room::FrameType type, const citra_room::MacAddress& to,
                           const citra_room::Bytes& data) {
        return gateway.inject_citra_frame_for_test(id, citra_wifi_frame_manual(
            *mac, to, data, frame_type_byte(type), 11));
    };
    citra_control::BeaconParams beacon;
    beacon.source_mac = *mac;
    beacon.network_info.host_mac_address = *mac;
    beacon.network_info.channel = 11;
    beacon.network_info.initialized = 1;
    beacon.network_info.wlan_comm_id = 0x00197110;
    beacon.network_info.network_id = 1;
    beacon.network_info.attributes = 0x8000;
    beacon.network_info.total_nodes = 1;
    beacon.network_info.max_nodes = 4;
    beacon.nodes.assign(4, citra_control::BeaconNodeInfo{});
    auto beacon_bytes = citra_control::build_beacon_frame(beacon);
    verify(beacon_bytes.ok(), "B17 host beacon builds");
    inject_wifi(citra_room::FrameType::Beacon, citra_room::broadcast_mac, beacon_bytes.value);

    citra_room::Bytes plain(48, 0);
    plain[0] = 0x32; plain[1] = 0xab; plain[2] = 0x98; plain[3] = 0x64;
    plain[4] = 1; plain[5] = 1;
    plain[24] = 3; plain[26] = 0x30; plain[27] = 0x39;
    std::copy(ip->begin(), ip->end(), plain.begin() + 20);
    std::copy(gu.begin(), gu.end(), plain.begin() + 32);
    room_client::ProxyPacket proxy;
    proxy.local.family = proxy.remote.family = room_client::Domain::Inet;
    proxy.local.ip = *ip;
    proxy.remote.ip = {192, 168, 1, 1};
    proxy.local.port = proxy.remote.port = 12345;
    proxy.protocol = room_client::SocketProtocol::Udp;
    proxy.broadcast = true;
    proxy.data = compress_payload(plain);
    auto before = gateway.counters();
    gateway.inject_room_message_for_test(id, proxy);
    check(gateway.counters().payload_rejected_source == before.payload_rejected_source + 1,
          "B17 room membership alone does not authorize a return");

    room_client::LdnPacket scan;
    scan.type = room_client::LdnType::Scan;
    scan.local_ip = *ip;
    scan.broadcast = true;
    gateway.inject_ldn_message_for_test(id, scan);
    citra_control::LdnNodeInfo node;
    node.mac_address = station_mac;
    node.node_id = 1;
    node.is_connected = 1;
    node.local_communication_version = 1;
    const auto node_bytes = citra_control::serialize_ldn_node_info(node);
    verify(node_bytes.ok(), "B17 LDN node builds");
    room_client::LdnPacket connect = scan;
    connect.type = room_client::LdnType::Connect;
    connect.data = node_bytes.value;
    gateway.inject_ldn_message_for_test(id, connect);
    before = gateway.counters();
    gateway.inject_room_message_for_test(id, proxy);
    check(gateway.counters().payload_rejected_source == before.payload_rejected_source + 1,
          "B17 admission before injection completion is insufficient");
    inject_wifi(citra_room::FrameType::AssociationResponse, station_mac,
                bytes_from_hex("3104000001c000083030303030303030"));
    citra_control::EapolLogoffPacket logoff;
    logoff.assigned_node_id = 2;
    logoff.connected_nodes = 2;
    logoff.max_nodes = 4;
    logoff.nodes[0].network_node_id = 1;
    logoff.nodes[1].network_node_id = 2;
    const auto logoff_bytes = citra_control::build_eapol_logoff_frame(logoff);
    verify(logoff_bytes.ok(), "B17 Citra logoff builds");
    inject_wifi(citra_room::FrameType::Data, station_mac, logoff_bytes.value);
    check(control_counter(gateway, "guest_inject_logoff_ok") == 1, "B17 guest injection completes");
    before = gateway.counters();
    gateway.inject_room_message_for_test(id, proxy);
    check(gateway.counters().payload_rejected_boundary == before.payload_rejected_boundary + 1,
          "B17 return without learned UDS data channel is rejected");

    citra_control::SecureDataFrame host;
    host.header.src_node_id = 1;
    host.header.dest_node_id = 0xffff;
    host.header.data_channel = 0;
    host.payload = plain;
    std::copy(xx.begin(), xx.end(), host.payload.begin() + 32);
    const auto zero_channel = citra_control::build_secure_data_frame(host);
    verify(zero_channel.ok(), "B17 zero-channel frame is structurally encodable");
    inject_wifi(citra_room::FrameType::Data, citra_room::broadcast_mac, zero_channel.value);
    before = gateway.counters();
    gateway.inject_room_message_for_test(id, proxy);
    check(gateway.counters().payload_rejected_boundary == before.payload_rejected_boundary + 1,
          "B17 zero data channel cannot establish a return profile");
    host.header.data_channel = 243;
    const auto host_bytes = citra_control::build_secure_data_frame(host);
    verify(host_bytes.ok(), "B17 host SecureData builds");
    inject_wifi(citra_room::FrameType::Data, citra_room::broadcast_mac, host_bytes.value);
    auto bad_port = proxy;
    bad_port.remote.port = 0;
    before = gateway.counters();
    gateway.inject_room_message_for_test(id, bad_port);
    check(gateway.counters().payload_rejected_boundary == before.payload_rejected_boundary + 1,
          "B17 mismatched UDP port is rejected");
    for (const bool broadcast : {true, false}) {
        proxy.broadcast = broadcast;
        gateway.clear_emitted_for_test();
        before = gateway.counters();
        gateway.inject_room_message_for_test(id, proxy);
        const auto emitted = emitted_of_kind(gateway, "citra.game.return");
        check(emitted.size() == 1 && gateway.counters().payload_forwarded == before.payload_forwarded + 1,
              "B17 admitted return is forwarded for broadcast and unicast");
        if (!emitted.empty()) {
            const auto bytes = bytes_from_hex(emitted[0].hex);
            const auto parsed = citra_control::parse_secure_data_frame(bytes.data(), bytes.size());
            check(parsed.ok() && parsed.value.header.src_node_id == 2 &&
                      parsed.value.header.dest_node_id == (broadcast ? 0xffff : 1) &&
                      parsed.value.header.data_channel == 243 && parsed.value.payload.size() == plain.size(),
                  "B17 LLC and SecureData carry the actual assigned node and separate data channel");
            check(parsed.ok() && hex_slice(hex_of(parsed.value.payload), 20, 4) == "6522df69" &&
                      hex_slice(hex_of(parsed.value.payload), 32, 4) == "b35ee27f",
                  "B17 return restores guest and host identity words");
        }
        check(drive(gateway, {&alpha}, [&] {
            for (const auto& message : alpha.messages()) {
                const auto* wifi = std::get_if<citra_room::WifiPacket>(&message);
                if (!wifi || wifi->type != citra_room::FrameType::Data || wifi->channel != 11 ||
                    wifi->transmitter != station_mac ||
                    wifi->destination != (broadcast ? citra_room::broadcast_mac : *mac)) {
                    continue;
                }
                const auto parsed = citra_control::parse_secure_data_frame(
                    wifi->data.data(), wifi->data.size());
                if (parsed.ok() && parsed.value.header.src_node_id == 2 &&
                    parsed.value.header.data_channel == 243) {
                    return true;
                }
            }
            return false;
        }, 2000), "B17 Citra receives the frame with the learned RF channel and station MAC");
    }
    // V-275: a short Citra response has an identity only in sender@20. The
    // body is control scalars, so requiring a body address loses the reply.
    host.payload.assign(36, 0);
    std::copy_n(plain.begin(), 32, host.payload.begin());
    host.payload[5] = 0;
    host.payload[24] = 1; host.payload[26] = 0; host.payload[27] = 0;
    std::copy(xx.begin(), xx.end(), host.payload.begin() + 20);
    host.payload[32] = 2; host.payload[33] = 1; host.payload[34] = 7;
    const auto response = citra_control::build_secure_data_frame(host);
    verify(response.ok(), "B17 short Citra response fixture builds");
    gateway.clear_emitted_for_test();
    before = gateway.counters();
    inject_wifi(citra_room::FrameType::Data, station_mac, response.value);
    const auto response_out = emitted_of_kind(gateway, "room.proxy.announce.host");
    check(response_out.size() == 1 && gateway.counters().proxy_frames_emitted == before.proxy_frames_emitted + 1,
          "B17 sender-only Citra response is forwarded under bidirectional opt-in");
    if (!response_out.empty()) {
        const auto compressed = bytes_from_hex(response_out[0].hex);
        citra_room::Bytes decoded;
        const bool ok = citra_gateway::decompress_proxy_frame(compressed, 65536, decoded, nullptr);
        auto expected = host.payload;
        std::copy(gu.begin(), gu.end(), expected.begin() + 20);
        check(ok && decoded == expected, "B17 sender mapping preserves every other response byte");
    }
    host.payload[20] = 9;
    const auto unknown_response = citra_control::build_secure_data_frame(host);
    verify(unknown_response.ok(), "B17 unmatched response fixture builds");
    const auto no_word_before = control_counter(gateway, "announce_no_identity_word");
    inject_wifi(citra_room::FrameType::Data, station_mac, unknown_response.value);
    check(control_counter(gateway, "announce_no_identity_word") == no_word_before + 1,
          "B17 opt-in does not bypass the identity requirement for an unmatched sender");
    // A different hall on the same Citra room connection must not reuse the
    // previous hall's successful injection or channel profile.
    beacon.network_info.network_id = 2;
    beacon_bytes = citra_control::build_beacon_frame(beacon);
    verify(beacon_bytes.ok(), "B17 replacement host beacon builds");
    inject_wifi(citra_room::FrameType::Beacon, citra_room::broadcast_mac, beacon_bytes.value);
    before = gateway.counters();
    gateway.inject_room_message_for_test(id, proxy);
    check(gateway.counters().payload_rejected_source == before.payload_rejected_source + 1,
          "B17 a new Citra hall invalidates the old admitted return node");
    dump_documents(gateway, "b17_game_return");
}
