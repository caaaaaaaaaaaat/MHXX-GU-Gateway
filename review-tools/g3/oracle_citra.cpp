// AUTO-GENERATED independent oracle. Lines below (namespace opener through static_assert)
// are copied VERBATIM from citra-master/src/core/hle/service/nwm/uds_data.h lines 15-60.
#include <cstdio>
#include <cstddef>
#include <array>
#include "common/common_types.h"
#include "common/swap.h"
#include "common/common_funcs.h"

namespace Service::NWM {

enum class SAP : u8 { SNAPExtensionUsed = 0xAA };

enum class PDUControl : u8 { UnnumberedInformation = 3 };

enum class EtherType : u16 { SecureData = 0x876D, EAPoL = 0x888E };

/*
 * 802.2 header, UDS packets always use SNAP for these headers,
 * which means the dsap and ssap are always SNAPExtensionUsed (0xAA)
 * and the OUI is always 0.
 */
struct LLCHeader {
    SAP dsap = SAP::SNAPExtensionUsed;
    SAP ssap = SAP::SNAPExtensionUsed;
    PDUControl control = PDUControl::UnnumberedInformation;
    std::array<u8, 3> OUI = {};
    enum_be<EtherType> protocol;
};

static_assert(sizeof(LLCHeader) == 8, "LLCHeader has the wrong size");

/*
 * Nintendo SecureData header, every UDS packet contains one,
 * it is used to store metadata about the transmission such as
 * the source and destination network node ids.
 */
struct SecureDataHeader {
    // TODO(Subv): It is likely that the first 4 bytes of this header are
    // actually part of another container protocol.
    u16_be protocol_size;
    INSERT_PADDING_BYTES(2);
    u16_be securedata_size;
    u8 is_management;
    u8 data_channel;
    u16_be sequence_number;
    u16_be dest_node_id;
    u16_be src_node_id;

    u32 GetActualDataSize() const {
        return protocol_size - sizeof(SecureDataHeader);
    }
};

static_assert(sizeof(SecureDataHeader) == 14, "SecureDataHeader has the wrong size");

} // namespace Service::NWM

int main() {
    using Service::NWM::LLCHeader;
    using Service::NWM::SecureDataHeader;
    std::printf("sizeof(LLCHeader)=%zu\n", sizeof(LLCHeader));
    std::printf("LLC dsap=%zu ssap=%zu control=%zu OUI=%zu protocol=%zu\n",
        offsetof(LLCHeader, dsap), offsetof(LLCHeader, ssap), offsetof(LLCHeader, control),
        offsetof(LLCHeader, OUI), offsetof(LLCHeader, protocol));
    std::printf("sizeof(SecureDataHeader)=%zu\n", sizeof(SecureDataHeader));
    std::printf("Secure protocol_size=%zu securedata_size=%zu is_management=%zu data_channel=%zu sequence_number=%zu dest_node_id=%zu src_node_id=%zu\n",
        offsetof(SecureDataHeader, protocol_size), offsetof(SecureDataHeader, securedata_size),
        offsetof(SecureDataHeader, is_management), offsetof(SecureDataHeader, data_channel),
        offsetof(SecureDataHeader, sequence_number), offsetof(SecureDataHeader, dest_node_id),
        offsetof(SecureDataHeader, src_node_id));
    std::printf("Combined = %zu bytes\n", sizeof(LLCHeader)+sizeof(SecureDataHeader));
    return 0;
}
