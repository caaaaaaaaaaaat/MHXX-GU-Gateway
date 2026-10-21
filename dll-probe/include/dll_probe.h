/* SPDX-License-Identifier: GPL-2.0-or-later
 * Original M3 infrastructure for this workspace; no emulator code copied.
 */
#ifndef CROSSPLAY_DLL_PROBE_H
#define CROSSPLAY_DLL_PROBE_H
#include <stdint.h>

#if defined(DP_BUILD_DLL)
#define DP_API __declspec(dllexport)
#else
#define DP_API
#endif
#ifdef __cplusplus
#define DP_NOEXCEPT noexcept
extern "C" {
#else
#define DP_NOEXCEPT
#endif
#define DP_CALL __cdecl
#define DP_ABI_VERSION UINT32_C(1)
#define DP_MAX_QUEUE UINT32_C(64)
#define DP_MAX_PAYLOAD UINT32_C(256)
#define DP_MAX_DELAY_MS UINT32_C(500)
#define DP_MAX_STOP_MS UINT32_C(5000)
#define DP_BROADCAST_NODE UINT32_C(65535)

typedef int32_t dp_result;
#define DP_OK ((dp_result)0)
#define DP_E_NULL ((dp_result)1)
#define DP_E_SIZE ((dp_result)2)
#define DP_E_VERSION ((dp_result)3)
#define DP_E_INVALID ((dp_result)4)
#define DP_E_NOT_RUNNING ((dp_result)5)
#define DP_E_ALREADY_RUNNING ((dp_result)6)
#define DP_E_NOT_STARTED ((dp_result)7)
#define DP_E_QUEUE_FULL ((dp_result)8)
#define DP_E_TIMEOUT ((dp_result)9)
#define DP_E_OS ((dp_result)10)
#define DP_E_INTERNAL ((dp_result)11)
#define DP_E_BUSY ((dp_result)12)
#define DP_STATE_FRESH UINT32_C(0)
#define DP_STATE_RUNNING UINT32_C(1)
#define DP_STATE_STOPPING UINT32_C(2)
#define DP_STATE_STOPPED UINT32_C(3)

/* Every struct uses the native Windows x64 ABI with default packing. */
typedef struct dp_limits {
    uint32_t struct_size;
    uint32_t abi_version;
    uint32_t max_queue;
    uint32_t max_payload;
    uint32_t max_delay_ms;
    uint32_t max_stop_ms;
    uint32_t reserved[2];
} dp_limits;

typedef struct dp_config {
    uint32_t struct_size;
    uint32_t abi_version;
    uint32_t queue_capacity;
    /* Bounded synthetic processing delay, useful for deterministic backpressure tests. */
    uint32_t worker_delay_ms;
    uint32_t reserved[4];
} dp_config;

typedef struct dp_record {
    uint32_t struct_size;
    uint32_t abi_version;
    uint32_t sequence;
    uint32_t source_node;       /* 1..16, synthetic only */
    uint32_t destination_node;  /* 1..16 or DP_BROADCAST_NODE */
    uint32_t channel;           /* 0..31 */
    uint32_t payload_size;      /* 1..DP_MAX_PAYLOAD */
    uint32_t reserved;
    uint8_t payload[DP_MAX_PAYLOAD];
} dp_record;

typedef struct dp_snapshot {
    uint32_t struct_size;
    uint32_t abi_version;
    uint32_t state;
    uint32_t queue_capacity;
    uint32_t queued;
    uint32_t in_flight;
    uint32_t worker_delay_ms;
    uint32_t last_sequence;
    uint32_t last_payload_size;
    uint32_t last_payload_checksum; /* FNV-1a 32, payload bytes only */
    uint64_t submitted;
    uint64_t completed;
    uint64_t payload_bytes;
    uint64_t rejected_full;
} dp_snapshot;

/*
 * HOST CONTRACT: serialize ALL exported calls, including snapshot/submit/stop,
 * across host threads. No concurrent/reentrant API calls are supported.
 * Keep the DLL loaded until stop returns DP_OK and all API calls have returned.
 * A timeout leaves STOPPING, rejects submissions, and requires a later stop retry.
 * Never call from DllMain/loader-lock context. No callbacks are accepted/invoked.
 * Pointer inputs must refer to accessible, correctly aligned objects for the call;
 * arbitrary dangling/non-null pointers are not validated. No STL crosses this ABI.
 * All struct inputs (also output headers) require exact size and ABI version 1.
 */
DP_API dp_result DP_CALL dp_get_abi_version(uint32_t* out_version) DP_NOEXCEPT;
DP_API dp_result DP_CALL dp_get_limits(dp_limits* out_limits) DP_NOEXCEPT;
DP_API dp_result DP_CALL dp_start(const dp_config* config) DP_NOEXCEPT;
DP_API dp_result DP_CALL dp_submit(const dp_record* record) DP_NOEXCEPT;
DP_API dp_result DP_CALL dp_snapshot_read(dp_snapshot* out_snapshot) DP_NOEXCEPT;
DP_API dp_result DP_CALL dp_stop(uint32_t timeout_ms) DP_NOEXCEPT;

/* The host resolves these by exact name with GetProcAddress (not link-time imports). */
typedef dp_result (DP_CALL *dp_get_abi_version_fn)(uint32_t*);
typedef dp_result (DP_CALL *dp_get_limits_fn)(dp_limits*);
typedef dp_result (DP_CALL *dp_start_fn)(const dp_config*);
typedef dp_result (DP_CALL *dp_submit_fn)(const dp_record*);
typedef dp_result (DP_CALL *dp_snapshot_read_fn)(dp_snapshot*);
typedef dp_result (DP_CALL *dp_stop_fn)(uint32_t);
#ifdef __cplusplus
}
static_assert(sizeof(dp_limits) == 32, "x64 limits ABI size");
static_assert(sizeof(dp_config) == 32, "x64 config ABI size");
static_assert(sizeof(dp_record) == 288, "x64 record ABI size");
static_assert(sizeof(dp_snapshot) == 72, "x64 snapshot ABI size");
#endif
#endif
