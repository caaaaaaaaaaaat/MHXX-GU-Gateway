// SPDX-License-Identifier: GPL-2.0-or-later
// Original self-owned Windows loader/test host. No emulator code or guest data.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <initializer_list>
#include "dll_probe.h"

namespace {
unsigned checks = 0;
unsigned suites = 0;
unsigned loads = 0;
unsigned unloads = 0;
[[noreturn]] void fail(const char* label) {
    std::printf("FAIL: %s (Win32 error=%lu)\n", label, GetLastError());
    std::printf("SUMMARY checks=%u failed=1 loads=%u unloads=%u\n", checks, loads, unloads);
    std::fflush(stdout);
    // On failure do NOT risk FreeLibrary with a live worker. Terminate this owned host.
    ExitProcess(2);
}
void check(bool value, const char* label) {
    ++checks;
    if (!value) fail(label);
}
void result(dp_result actual, dp_result expected, const char* label) {
    if (actual != expected) std::printf("actual=%ld expected=%ld\n", (long)actual, (long)expected);
    check(actual == expected, label);
}
void suite(const char* name, unsigned before) {
    ++suites;
    std::printf("PASS suite=%s checks=%u\n", name, checks - before);
}
struct Api {
    HMODULE module;
    dp_get_abi_version_fn version;
    dp_get_limits_fn limits;
    dp_start_fn start;
    dp_submit_fn submit;
    dp_snapshot_read_fn snapshot;
    dp_stop_fn stop;
};
template <typename T> T resolve(HMODULE module, const char* name) {
    const FARPROC raw = GetProcAddress(module, name);
    check(raw != nullptr, name);
    T typed = nullptr;
    static_assert(sizeof(typed) == sizeof(raw), "Windows function pointer representation");
    std::memcpy(&typed, &raw, sizeof(typed));
    return typed;
}
Api load(const wchar_t* path) {
    Api a{};
    a.module = LoadLibraryW(path);
    check(a.module != nullptr, "LoadLibraryW owned absolute path");
    ++loads;
    a.version = resolve<dp_get_abi_version_fn>(a.module, "dp_get_abi_version");
    a.limits = resolve<dp_get_limits_fn>(a.module, "dp_get_limits");
    a.start = resolve<dp_start_fn>(a.module, "dp_start");
    a.submit = resolve<dp_submit_fn>(a.module, "dp_submit");
    a.snapshot = resolve<dp_snapshot_read_fn>(a.module, "dp_snapshot_read");
    a.stop = resolve<dp_stop_fn>(a.module, "dp_stop");
    return a;
}
dp_config config(uint32_t capacity = 4, uint32_t delay = 0) {
    dp_config c{};
    c.struct_size = sizeof(c);
    c.abi_version = DP_ABI_VERSION;
    c.queue_capacity = capacity;
    c.worker_delay_ms = delay;
    return c;
}
dp_record record(uint32_t sequence = 1, uint32_t size = DP_MAX_PAYLOAD) {
    dp_record r{};
    r.struct_size = sizeof(r);
    r.abi_version = DP_ABI_VERSION;
    r.sequence = sequence;
    r.source_node = 1;
    r.destination_node = DP_BROADCAST_NODE;
    r.channel = 31;
    r.payload_size = size;
    for (uint32_t i = 0; i < DP_MAX_PAYLOAD; ++i) r.payload[i] = (uint8_t)i;
    return r;
}
dp_snapshot read_snapshot(const Api& a) {
    dp_snapshot s{};
    s.struct_size = sizeof(s);
    s.abi_version = DP_ABI_VERSION;
    if (a.snapshot(&s) != DP_OK) fail("snapshot helper");
    return s;
}
bool wait_inflight(const Api& a) {
    const ULONGLONG deadline = GetTickCount64() + 2000;
    do {
        if (read_snapshot(a).in_flight == 1) return true;
        Sleep(1);
    } while (GetTickCount64() < deadline);
    return false;
}
void unload(Api& a, const wchar_t* path) {
    const dp_snapshot s = read_snapshot(a);
    check(s.state == DP_STATE_STOPPED, "FreeLibrary precondition: STOPPED");
    check(s.queued == 0 && s.in_flight == 0, "FreeLibrary precondition: no in-flight work");
    check(FreeLibrary(a.module) != FALSE, "FreeLibrary after stop joined");
    ++unloads;
    a = {};
    check(GetModuleHandleW(path) == nullptr, "module absent after FreeLibrary");
}
void test_loader_and_fresh(Api& a) {
    const unsigned before = checks;
    check(GetProcAddress(a.module, "definitely_not_an_export") == nullptr, "unknown export absent");
    uint32_t version = 0;
    result(a.version(nullptr), DP_E_NULL, "null version");
    result(a.version(&version), DP_OK, "version read");
    check(version == DP_ABI_VERSION, "version 1");
    result(a.limits(nullptr), DP_E_NULL, "null limits");
    dp_limits l{};
    l.struct_size = sizeof(l);
    l.abi_version = DP_ABI_VERSION;
    result(a.limits(&l), DP_OK, "limits read");
    check(l.max_queue == 64 && l.max_payload == 256 && l.max_delay_ms == 500 &&
          l.max_stop_ms == 5000 && l.reserved[0] == 0 && l.reserved[1] == 0, "hard limits");
    l.struct_size = 0;
    result(a.limits(&l), DP_E_SIZE, "limits undersize");
    l.struct_size = sizeof(l) + 1;
    result(a.limits(&l), DP_E_SIZE, "limits oversize");
    l.struct_size = sizeof(l);
    l.abi_version = 2;
    result(a.limits(&l), DP_E_VERSION, "limits version mismatch");
    const dp_snapshot s = read_snapshot(a);
    check(s.state == DP_STATE_FRESH && s.submitted == 0 && s.completed == 0, "fresh uninitialized snapshot");
    result(a.stop(0), DP_E_NOT_STARTED, "stop before start");
    auto r = record();
    result(a.submit(&r), DP_E_NOT_RUNNING, "submit before start");
    suite("loader-version-fresh", before);
}
void test_invalid(Api& a) {
    const unsigned before = checks;
    result(a.start(nullptr), DP_E_NULL, "null config");
    result(a.submit(nullptr), DP_E_NULL, "null record");
    result(a.snapshot(nullptr), DP_E_NULL, "null snapshot");
    for (uint32_t size : {0U, (uint32_t)sizeof(dp_config) - 1, (uint32_t)sizeof(dp_config) + 1}) {
        auto c = config(); c.struct_size = size;
        result(a.start(&c), DP_E_SIZE, "config exact size required");
    }
    auto c = config(); c.abi_version = 0;
    result(a.start(&c), DP_E_VERSION, "config version mismatch");
    for (uint32_t capacity : {0U, 65U, UINT32_MAX}) {
        c = config(capacity);
        result(a.start(&c), DP_E_INVALID, "queue capacity bounds");
    }
    c = config(1, DP_MAX_DELAY_MS + 1);
    result(a.start(&c), DP_E_INVALID, "delay bound");
    for (unsigned i = 0; i < 4; ++i) {
        c = config(); c.reserved[i] = 1;
        result(a.start(&c), DP_E_INVALID, "config reserved must be zero");
    }
    auto r = record();
    for (uint32_t size : {0U, (uint32_t)sizeof(dp_record) - 1, (uint32_t)sizeof(dp_record) + 1}) {
        r = record(); r.struct_size = size;
        result(a.submit(&r), DP_E_SIZE, "record exact size required");
    }
    r = record(); r.abi_version = 2;
    result(a.submit(&r), DP_E_VERSION, "record version mismatch");
    for (uint32_t size : {0U, 257U, UINT32_MAX}) {
        r = record(); r.payload_size = size;
        result(a.submit(&r), DP_E_INVALID, "payload bounds");
    }
    for (uint32_t node : {0U, 17U, UINT32_MAX}) {
        r = record(); r.source_node = node;
        result(a.submit(&r), DP_E_INVALID, "source node bounds");
        r = record(); r.destination_node = node;
        result(a.submit(&r), DP_E_INVALID, "destination node bounds");
    }
    r = record(); r.channel = 32;
    result(a.submit(&r), DP_E_INVALID, "channel bound");
    r = record(); r.reserved = 1;
    result(a.submit(&r), DP_E_INVALID, "record reserved must be zero");
    dp_snapshot s{}; s.abi_version = DP_ABI_VERSION;
    for (uint32_t size : {0U, (uint32_t)sizeof(dp_snapshot) - 1, (uint32_t)sizeof(dp_snapshot) + 1}) {
        s.struct_size = size;
        result(a.snapshot(&s), DP_E_SIZE, "snapshot exact size required");
    }
    s.struct_size = sizeof(s); s.abi_version = 2;
    result(a.snapshot(&s), DP_E_VERSION, "snapshot version mismatch");
    result(a.stop(DP_MAX_STOP_MS + 1), DP_E_INVALID, "stop timeout bound");
    const auto after = read_snapshot(a);
    check(after.state == DP_STATE_FRESH && after.submitted == 0, "invalid calls preserve lifecycle");
    suite("invalid-null-size-limits", before);
}
void test_copy_and_restart(Api& a) {
    const unsigned before = checks;
    auto c = config(DP_MAX_QUEUE, DP_MAX_DELAY_MS);
    result(a.start(&c), DP_OK, "start after invalid failures at exact max limits");
    result(a.start(&c), DP_E_ALREADY_RUNNING, "duplicate start");
    auto r = record(42);
    const auto original = r;
    result(a.submit(&r), DP_OK, "submit exact max payload");
    check(std::memcmp(&r, &original, sizeof(r)) == 0, "submit never modifies caller record");
    // Mutate input immediately: worker must only read its private copy.
    std::memset(r.payload, 0xEE, sizeof(r.payload));
    r.sequence = 999;
    result(a.stop(DP_MAX_STOP_MS), DP_OK, "stop drains copied fixture and joins");
    auto s = read_snapshot(a);
    // Independent hand-fixed FNV-1a oracle for bytes 00..FF, not DLL-generated.
    check(s.completed == 1 && s.submitted == 1 && s.payload_bytes == 256 &&
          s.last_sequence == 42 && s.last_payload_checksum == UINT32_C(0x90a458c5), "deep copy golden checksum and sequence");
    check(s.last_payload_size == 256 && s.queued == 0 && s.in_flight == 0 &&
          s.state == DP_STATE_STOPPED, "drained snapshot");
    result(a.stop(0), DP_OK, "duplicate stop idempotent");
    result(a.submit(&original), DP_E_NOT_RUNNING, "submit after stopped");
    c = config(1, 0);
    result(a.start(&c), DP_OK, "restart same module");
    s = read_snapshot(a);
    check(s.submitted == 0 && s.completed == 0 && s.rejected_full == 0, "restart resets counters");
    r = record(77, 1); r.source_node = 16; r.destination_node = 16; r.channel = 0;
    result(a.submit(&r), DP_OK, "minimum payload and endpoint limits");
    result(a.stop(DP_MAX_STOP_MS), DP_OK, "restart stop");
    s = read_snapshot(a);
    check(s.completed == 1 && s.payload_bytes == 1 && s.last_sequence == 77, "restart processed");
    suite("copy-drain-restart", before);
}
void test_backpressure_timeout(Api& a) {
    const unsigned before = checks;
    auto c = config(2, 500);
    result(a.start(&c), DP_OK, "backpressure start");
    auto r = record(100, 1);
    result(a.submit(&r), DP_OK, "submit in-flight fixture");
    check(wait_inflight(a), "observe worker processing within 2s");
    r.sequence = 101; result(a.submit(&r), DP_OK, "queue first");
    r.sequence = 102; result(a.submit(&r), DP_OK, "queue second reaches capacity");
    r.sequence = 103; result(a.submit(&r), DP_E_QUEUE_FULL, "queue full bounded rejection");
    const auto full = read_snapshot(a);
    check(full.queued == 2 && full.in_flight == 1 && full.submitted == 3 &&
          full.rejected_full == 1, "queue bound plus one in-flight");
    result(a.stop(0), DP_E_TIMEOUT, "zero stop timeout retains live module");
    check(read_snapshot(a).state == DP_STATE_STOPPING, "timeout leaves STOPPING");
    result(a.submit(&r), DP_E_NOT_RUNNING, "stopping rejects submit");
    result(a.start(&c), DP_E_BUSY, "stopping rejects restart");
    result(a.stop(DP_MAX_STOP_MS), DP_OK, "retry timeout drains and joins without callbacks");
    const auto s = read_snapshot(a);
    check(s.completed == 3 && s.submitted == 3 && s.payload_bytes == 3 &&
          s.last_sequence == 102 && s.queued == 0 && s.in_flight == 0, "FIFO drain after timeout");
    suite("queue-full-timeout-recovery", before);
}
void test_idle_stop(Api& a) {
    const unsigned before = checks;
    auto c = config(1, DP_MAX_DELAY_MS);
    result(a.start(&c), DP_OK, "idle start no callbacks");
    const auto running = read_snapshot(a);
    check(running.state == DP_STATE_RUNNING && running.queued == 0 && running.in_flight == 0,
          "idle worker has no pending user callback");
    result(a.stop(DP_MAX_STOP_MS), DP_OK, "idle event wait wakes and joins");
    const auto stopped = read_snapshot(a);
    check(stopped.state == DP_STATE_STOPPED && stopped.submitted == 0 && stopped.completed == 0,
          "idle stop consumed no fixture");
    result(a.stop(0), DP_OK, "idle duplicate stop");
    suite("idle-no-callback-stop", before);
}
void test_repeated_load(const wchar_t* path) {
    const unsigned before = checks;
    DWORD handles_before = 0;
    check(GetProcessHandleCount(GetCurrentProcess(), &handles_before) != FALSE, "get handle baseline");
    for (unsigned cycle = 0; cycle < 32; ++cycle) {
        auto a = load(path);
        check(read_snapshot(a).state == DP_STATE_FRESH, "reload resets fresh state");
        auto bad = config(0);
        result(a.start(&bad), DP_E_INVALID, "cycle invalid start");
        auto c = config(1);
        result(a.start(&c), DP_OK, "cycle recovery start");
        auto r = record(cycle, 1);
        result(a.submit(&r), DP_OK, "cycle submit");
        result(a.stop(DP_MAX_STOP_MS), DP_OK, "cycle stop joins");
        const auto s = read_snapshot(a);
        check(s.completed == 1 && s.last_sequence == cycle, "cycle exactly one fixture");
        result(a.stop(0), DP_OK, "cycle duplicate stop");
        unload(a, path);
    }
    DWORD handles_after = 0;
    check(GetProcessHandleCount(GetCurrentProcess(), &handles_after) != FALSE, "get handle final");
    std::printf("EVIDENCE cycles=32 handles_before=%lu handles_after=%lu\n", handles_before, handles_after);
    check(handles_after == handles_before, "no net handle growth across 32 cycles");
    suite("32-load-stop-unload-cycles", before);
}
} // namespace
int wmain(int argc, wchar_t** argv) {
    if (argc != 2) {
        std::printf("Usage: loader_host.exe <absolute owned DLL path>\n");
        return 64;
    }
    wchar_t path[32768]{};
    const DWORD length = GetFullPathNameW(argv[1], 32768, path, nullptr);
    check(length != 0 && length < 32700, "resolve owned DLL full path");
    wchar_t missing[32768]{};
    std::swprintf(missing, 32768, L"%ls.absent-test-file", path);
    check(LoadLibraryW(missing) == nullptr, "missing DLL failure is recoverable");
    auto a = load(path);
    test_loader_and_fresh(a);
    test_invalid(a);
    test_copy_and_restart(a);
    test_backpressure_timeout(a);
    test_idle_stop(a);
    unload(a, path);
    test_repeated_load(path);
    std::printf("SUMMARY suites=%u checks=%u failed=0 loads=%u unloads=%u\n", suites, checks, loads, unloads);
    return 0;
}
