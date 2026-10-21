// SPDX-License-Identifier: GPL-2.0-or-later
// Original implementation for this workspace. No emulator source or hook code.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include "dll_probe.h"

namespace {
struct State {
    SRWLOCK lock;
    HANDLE wake;
    HANDLE worker;
    dp_snapshot stats;
    dp_result worker_result;
    uint32_t head;
    uint32_t tail;
    dp_record queue[DP_MAX_QUEUE];
};
// Constant/POD initialization only; no custom DllMain or global C++ destructor.
State g = {SRWLOCK_INIT, nullptr, nullptr, {}, DP_OK, 0, 0, {}};
class Guard {
public:
    Guard() noexcept { AcquireSRWLockExclusive(&g.lock); }
    ~Guard() noexcept { ReleaseSRWLockExclusive(&g.lock); }
    Guard(const Guard&) = delete;
    Guard& operator=(const Guard&) = delete;
};
template <typename T> dp_result header(const T* p) noexcept {
    if (p == nullptr) return DP_E_NULL;
    if (p->struct_size != sizeof(T)) return DP_E_SIZE;
    if (p->abi_version != DP_ABI_VERSION) return DP_E_VERSION;
    return DP_OK;
}
uint32_t checksum(const dp_record& r) noexcept {
    uint32_t value = UINT32_C(2166136261);
    for (uint32_t i = 0; i < r.payload_size; ++i) {
        value = (value ^ r.payload[i]) * UINT32_C(16777619);
    }
    return value;
}
DWORD worker_body() {
    for (;;) {
        dp_record local{};
        uint32_t delay = 0;
        bool have_record = false;
        {
            Guard guard;
            if (g.stats.queued != 0) {
                local = g.queue[g.head]; // Copy internal queue storage before releasing lock.
                g.head = (g.head + 1) % g.stats.queue_capacity;
                --g.stats.queued;
                g.stats.in_flight = 1;
                delay = g.stats.worker_delay_ms;
                have_record = true;
            } else if (g.stats.state == DP_STATE_STOPPING) {
                return 0; // All accepted records drained before the thread exits.
            }
        }
        if (have_record) {
            if (delay != 0) Sleep(delay); // Bounded; no host callbacks or network calls.
            const uint32_t hash = checksum(local);
            Guard guard;
            ++g.stats.completed;
            g.stats.payload_bytes += local.payload_size;
            g.stats.last_sequence = local.sequence;
            g.stats.last_payload_size = local.payload_size;
            g.stats.last_payload_checksum = hash;
            g.stats.in_flight = 0;
        } else if (WaitForSingleObject(g.wake, INFINITE) != WAIT_OBJECT_0) {
            Guard guard;
            g.worker_result = DP_E_OS;
            g.stats.state = DP_STATE_STOPPING;
            return 1;
        }
    }
}
DWORD WINAPI worker_entry(void*) noexcept {
    // The worker is also an ABI boundary. Current worker_body only calls nonthrowing code.
    try { return worker_body(); }
    catch (...) {
        Guard guard;
        g.worker_result = DP_E_INTERNAL;
        g.stats.state = DP_STATE_STOPPING;
        return 1;
    }
}
dp_result start_impl(const dp_config* c) {
    const dp_result h = header(c);
    if (h != DP_OK) return h;
    if (c->queue_capacity == 0 || c->queue_capacity > DP_MAX_QUEUE ||
        c->worker_delay_ms > DP_MAX_DELAY_MS) return DP_E_INVALID;
    for (const uint32_t item : c->reserved) if (item != 0) return DP_E_INVALID;
    Guard guard;
    if (g.stats.state == DP_STATE_RUNNING) return DP_E_ALREADY_RUNNING;
    if (g.stats.state == DP_STATE_STOPPING) return DP_E_BUSY;
    HANDLE wake = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    if (wake == nullptr) return DP_E_OS;
    g.wake = wake;
    // Worker blocks on g.lock until all configuration below has been committed.
    HANDLE thread = CreateThread(nullptr, 0, worker_entry, nullptr, 0, nullptr);
    if (thread == nullptr) {
        g.wake = nullptr;
        CloseHandle(wake);
        return DP_E_OS;
    }
    g.worker = thread;
    g.stats = {};
    g.stats.struct_size = sizeof(dp_snapshot);
    g.stats.abi_version = DP_ABI_VERSION;
    g.stats.state = DP_STATE_RUNNING;
    g.stats.queue_capacity = c->queue_capacity;
    g.stats.worker_delay_ms = c->worker_delay_ms;
    g.worker_result = DP_OK;
    g.head = 0;
    g.tail = 0;
    return DP_OK;
}
dp_result submit_impl(const dp_record* r) {
    const dp_result h = header(r);
    if (h != DP_OK) return h;
    if (r->payload_size == 0 || r->payload_size > DP_MAX_PAYLOAD ||
        r->source_node < 1 || r->source_node > 16 || r->channel > 31 ||
        (r->destination_node != DP_BROADCAST_NODE &&
         (r->destination_node < 1 || r->destination_node > 16)) || r->reserved != 0)
        return DP_E_INVALID;
    Guard guard;
    if (g.stats.state != DP_STATE_RUNNING) return DP_E_NOT_RUNNING;
    if (g.stats.queued == g.stats.queue_capacity) {
        ++g.stats.rejected_full;
        return DP_E_QUEUE_FULL;
    }
    // Copy ONLY caller-provided synthetic fixture data. No host/guest memory inspection.
    g.queue[g.tail] = *r;
    g.tail = (g.tail + 1) % g.stats.queue_capacity;
    ++g.stats.queued;
    ++g.stats.submitted;
    SetEvent(g.wake);
    return DP_OK;
}
dp_result stop_impl(uint32_t timeout_ms) {
    if (timeout_ms > DP_MAX_STOP_MS) return DP_E_INVALID;
    HANDLE thread = nullptr;
    {
        Guard guard;
        if (g.stats.state == DP_STATE_FRESH) return DP_E_NOT_STARTED;
        if (g.stats.state == DP_STATE_STOPPED) return DP_OK; // Explicitly idempotent.
        g.stats.state = DP_STATE_STOPPING;
        thread = g.worker;
        SetEvent(g.wake);
    }
    // This waits for the actual thread handle: a successful wait is a worker join.
    // Host MUST NOT invoke another API/unload concurrently with this call.
    const DWORD waited = WaitForSingleObject(thread, timeout_ms);
    if (waited == WAIT_TIMEOUT) return DP_E_TIMEOUT; // Keep handles/state for retry.
    if (waited != WAIT_OBJECT_0) return DP_E_OS;
    Guard guard;
    CloseHandle(g.worker);
    CloseHandle(g.wake);
    g.worker = nullptr;
    g.wake = nullptr;
    g.stats.state = DP_STATE_STOPPED;
    g.stats.in_flight = 0;
    return g.worker_result;
}
} // namespace

// No exception is permitted to cross the C ABI. No allocations/STL cross the DLL boundary.
extern "C" DP_API dp_result DP_CALL dp_get_abi_version(uint32_t* out) noexcept {
    try {
        if (out == nullptr) return DP_E_NULL;
        *out = DP_ABI_VERSION;
        return DP_OK;
    } catch (...) { return DP_E_INTERNAL; }
}
extern "C" DP_API dp_result DP_CALL dp_get_limits(dp_limits* out) noexcept {
    try {
        const dp_result h = header(out);
        if (h != DP_OK) return h;
        const dp_limits result = {sizeof(dp_limits), DP_ABI_VERSION, DP_MAX_QUEUE,
                                  DP_MAX_PAYLOAD, DP_MAX_DELAY_MS, DP_MAX_STOP_MS, {0, 0}};
        *out = result;
        return DP_OK;
    } catch (...) { return DP_E_INTERNAL; }
}
extern "C" DP_API dp_result DP_CALL dp_start(const dp_config* c) noexcept {
    try { return start_impl(c); } catch (...) { return DP_E_INTERNAL; }
}
extern "C" DP_API dp_result DP_CALL dp_submit(const dp_record* r) noexcept {
    try { return submit_impl(r); } catch (...) { return DP_E_INTERNAL; }
}
extern "C" DP_API dp_result DP_CALL dp_snapshot_read(dp_snapshot* out) noexcept {
    try {
        const dp_result h = header(out);
        if (h != DP_OK) return h;
        Guard guard;
        *out = g.stats;
        out->struct_size = sizeof(dp_snapshot);
        out->abi_version = DP_ABI_VERSION;
        return DP_OK;
    } catch (...) { return DP_E_INTERNAL; }
}
extern "C" DP_API dp_result DP_CALL dp_stop(uint32_t timeout_ms) noexcept {
    try { return stop_impl(timeout_ms); } catch (...) { return DP_E_INTERNAL; }
}
