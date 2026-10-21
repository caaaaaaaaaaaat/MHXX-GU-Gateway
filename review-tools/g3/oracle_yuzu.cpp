#include <cstdio>
#include <cstddef>
#include <cstring>
#include <string_view>
#include <algorithm>
#include "core/hle/service/ldn/ldn_types.h"
using namespace Service::LDN;
#define O(T,m) std::printf("  %-42s @0x%zX\n", #T "." #m, offsetof(T,m))
int main(){
    std::printf("sizeof(NodeInfo)=0x%zX sizeof(NetworkInfo)=0x%zX sizeof(LdnNetworkInfo)=0x%zX sizeof(CommonNetworkInfo)=0x%zX sizeof(NetworkId)=0x%zX sizeof(IntentId)=0x%zX sizeof(SessionId)=0x%zX sizeof(Ssid)=0x%zX sizeof(MacAddress)=0x%zX\n",
        sizeof(NodeInfo), sizeof(NetworkInfo), sizeof(LdnNetworkInfo), sizeof(CommonNetworkInfo), sizeof(NetworkId), sizeof(IntentId), sizeof(SessionId), sizeof(Ssid), sizeof(MacAddress));
    O(NodeInfo, ipv4_address); O(NodeInfo, mac_address); O(NodeInfo, node_id); O(NodeInfo, is_connected);
    O(NodeInfo, user_name); O(NodeInfo, local_communication_version);
    O(NetworkInfo, network_id.intent_id.local_communication_id); O(NetworkInfo, network_id.intent_id.scene_id);
    O(NetworkInfo, network_id.session_id.high); O(NetworkInfo, network_id.session_id.low);
    O(NetworkInfo, common.bssid); O(NetworkInfo, common.ssid); O(NetworkInfo, common.ssid.length); O(NetworkInfo, common.ssid.raw);
    O(NetworkInfo, common.channel); O(NetworkInfo, common.link_level); O(NetworkInfo, common.network_type);
    O(NetworkInfo, ldn.security_parameter); O(NetworkInfo, ldn.security_mode);
    O(NetworkInfo, ldn.station_accept_policy); O(NetworkInfo, ldn.has_action_frame);
    O(NetworkInfo, ldn.node_count_max); O(NetworkInfo, ldn.node_count); O(NetworkInfo, ldn.nodes);
    O(NetworkInfo, ldn.advertise_data_size); O(NetworkInfo, ldn.advertise_data); O(NetworkInfo, ldn.random_authentication_id);
    return 0;
}
