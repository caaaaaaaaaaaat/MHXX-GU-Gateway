// SPDX-License-Identifier: GPL-3.0-or-later
#include "yuzu_capture/relay.hpp"
#include <enet/enet.h>
#include <chrono>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>

namespace {
unsigned number(const std::string& text,unsigned low,unsigned high) {
    std::size_t used=0;
    const auto value=std::stoul(text,&used);
    if (used!=text.size() || value<low || value>high) throw std::runtime_error("numeric argument outside range");
    return static_cast<unsigned>(value);
}
}
int main(int argc,char** argv) {
    yuzu_capture::Options options;
    options.identity.manifest_id="yuzu-capture-unassigned";
    options.identity.build_id="yuzu-capture/1";
    options.identity.platform="yuzu";
    options.identity.role="observer";
    options.identity.run_id=citra_gateway::trace_utc_now()+"-"+std::to_string(citra_gateway::trace_monotonic_ms());
    unsigned seconds=60;
    try {
        for (int i=1;i<argc;++i) {
            const std::string key=argv[i];
            if (key=="--help") {
                std::cout<<"yuzu-capture: loopback v1 ENet recording relay; NOT a gameplay translator\n"
                    <<"--listen-port N --room-port N --seconds N --max-peers N\n"
                    <<"--trace-out PATH [--trace-raw] --manifest ID --build ID --stage-file PATH\n"
                    <<"Binds only 127.0.0.1; each client has an independent upstream connection.\n";
                return 0;
            }
            if (key=="--trace-raw") { options.trace_raw=true; continue; }
            if (++i>=argc) throw std::runtime_error("missing flag value");
            const std::string value=argv[i];
            if (key=="--listen-port") options.listen_port=static_cast<std::uint16_t>(number(value,1,65535));
            else if (key=="--room-port") options.room_port=static_cast<std::uint16_t>(number(value,1,65535));
            else if (key=="--max-peers") options.max_peers=number(value,1,16);
            else if (key=="--seconds") seconds=number(value,1,86400);
            else if (key=="--trace-out") { if (value.empty()) throw std::runtime_error("empty trace path"); options.trace_path=value; }
            else if (key=="--manifest") options.identity.manifest_id=value;
            else if (key=="--build") options.identity.build_id=value;
            else if (key=="--stage-file") options.stage_file=value;
            else throw std::runtime_error("unknown option");
        }
        if (options.trace_raw && options.trace_path.empty()) throw std::runtime_error("--trace-raw requires --trace-out");
    } catch (const std::exception& error) { std::cerr<<"usage error: "<<error.what()<<'\n'; return 2; }
    if (enet_initialize()!=0) { std::cerr<<"ENet initialization failed\n"; return 3; }
    int code=0;
    try {
        yuzu_capture::Relay relay(options);
        relay.open();
        std::cout<<"CAPTURE_READY bind=127.0.0.1:"<<relay.port()<<" upstream=127.0.0.1:"<<options.room_port
            <<" run_id="<<options.identity.run_id<<" raw="<<options.trace_raw<<std::endl;
        const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(seconds);
        while (std::chrono::steady_clock::now()<deadline && !relay.failed()) {
            relay.tick(); std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        relay.close();
        const auto stats=relay.stats();
        code=relay.failed()?4:0;
        std::cout<<"CAPTURE_RESULT connected="<<stats.connected<<" up="<<stats.forwarded_up
            <<" down="<<stats.forwarded_down<<" rejected="<<stats.rejected
            <<" timeouts="<<stats.timeouts<<" decode_failures="<<stats.decode_failures
            <<" trace_failures="<<stats.trace_failures<<" exit="<<code<<'\n';
    } catch (const std::exception& error) { std::cerr<<"capture failed: "<<error.what()<<'\n'; code=3; }
    enet_deinitialize();
    return code;
}
