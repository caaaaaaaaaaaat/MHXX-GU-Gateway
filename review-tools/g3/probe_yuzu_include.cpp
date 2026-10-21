#include <cstdio>
#include <cstddef>
#include "core/hle/service/ldn/ldn_types.h"
int main(){ std::printf("%zu %zu\n", sizeof(Service::LDN::NodeInfo), sizeof(Service::LDN::NetworkInfo)); return 0; }
