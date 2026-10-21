/* SPDX-License-Identifier: GPL-2.0-or-later
 * Original C11 ABI compilation test; no external source copied.
 */
#include <stddef.h>
#include "dll_probe.h"
_Static_assert(sizeof(dp_result) == 4, "result ABI");
_Static_assert(sizeof(dp_limits) == 32, "limits ABI");
_Static_assert(sizeof(dp_config) == 32, "config ABI");
_Static_assert(sizeof(dp_record) == 288, "record ABI");
_Static_assert(sizeof(dp_snapshot) == 72, "snapshot ABI");
_Static_assert(offsetof(dp_record, payload) == 32, "payload offset");
_Static_assert(offsetof(dp_snapshot, submitted) == 40, "counter alignment");
int dp_c_header_smoke(void) {
    dp_get_abi_version_fn version = 0;
    dp_get_limits_fn limits = 0;
    dp_start_fn start = 0;
    dp_submit_fn submit = 0;
    dp_snapshot_read_fn snapshot = 0;
    dp_stop_fn stop = 0;
    return version == 0 && limits == 0 && start == 0 && submit == 0 && snapshot == 0 && stop == 0;
}
