#include <cstdio>
#include <cstddef>
#include "core/hle/service/nwm/uds_data.h"
int main(){
    std::printf("LLC=%zu SEC=%zu\n", sizeof(Service::NWM::LLCHeader), sizeof(Service::NWM::SecureDataHeader));
    return 0;
}
