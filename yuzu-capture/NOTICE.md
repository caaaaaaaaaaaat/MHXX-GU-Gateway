# License and provenance

New yuzu-capture code: SPDX-License-Identifier: GPL-3.0-or-later.
GPL text is in LICENSE.txt. No game assets, saves, keys or game captures are included.

Build-time source dependencies remain in their original directories:

- Yuzu/Citra room codec and gateway trace modules: respective SPDX notices apply;
  GPL-2.0-or-later/GPL-3.0-or-later code is combined under GPL-3.0-or-later here.
- Original Yuzu Room/Packet/VerifyUser sources are linked only by the synthetic test;
  upstream files are not modified. Source hashes are checked across the build.
- ENet 1.3.18: MIT; source/license under room-transport/vendor/enet-*.
- fmt 10.2.1: MIT; source/license under room-transport/vendor/fmt-*.
- zstd 1.5.7: BSD/GPL dual license; local static library. BSD license copied as
  THIRD-PARTY-zstd-LICENSE.txt.

The application links the existing trace.cpp implementation directly; no recorder
implementation has been copied. A future shared trace target may reduce dependencies.
