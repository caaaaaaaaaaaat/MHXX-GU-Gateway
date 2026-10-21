# SPDX-License-Identifier: GPL-3.0-or-later
$ErrorActionPreference = 'Stop'
& node --test (Join-Path $PSScriptRoot 'trace-audit.test.mjs') (Join-Path $PSScriptRoot 'yuzu-preflight.test.mjs') (Join-Path $PSScriptRoot 'app-profile.test.mjs') (Join-Path $PSScriptRoot 'uds-advertisement.test.mjs') (Join-Path $PSScriptRoot 'mhxx-endpoint.test.mjs') (Join-Path $PSScriptRoot 'mh-identity.test.mjs') (Join-Path $PSScriptRoot 'mhgu-peer-descriptor.test.mjs') (Join-Path $PSScriptRoot 'mhgu-peer-list.test.mjs')
if ($LASTEXITCODE -ne 0) { throw "trace audit tests failed: $LASTEXITCODE" }
& node --test (Join-Path $PSScriptRoot 'mh-peer-list-fragment.test.mjs')
if ($LASTEXITCODE -ne 0) { throw "peer list fragment tests failed: $LASTEXITCODE" }
& node --test (Join-Path $PSScriptRoot 'mh-peer-list-assembly.test.mjs')
if ($LASTEXITCODE -ne 0) { throw "peer list assembly tests failed: $LASTEXITCODE" }
& node --test (Join-Path $PSScriptRoot 'mhxx-working-descriptor.test.mjs')
if ($LASTEXITCODE -ne 0) { throw "MHXX working descriptor tests failed: $LASTEXITCODE" }
& node --test (Join-Path $PSScriptRoot 'mh-base-peer-endpoint.test.mjs')
if ($LASTEXITCODE -ne 0) { throw "base peer endpoint tests failed: $LASTEXITCODE" }
& node --test (Join-Path $PSScriptRoot 'mhxx-stream-chunk.test.mjs')
if ($LASTEXITCODE -ne 0) { throw "MHXX stream chunk tests failed: $LASTEXITCODE" }
& node --test (Join-Path $PSScriptRoot 'mh-stream-chunk.test.mjs')
if ($LASTEXITCODE -ne 0) { throw "shared stream chunk tests failed: $LASTEXITCODE" }
& node --test (Join-Path $PSScriptRoot 'mh-system-stream.test.mjs')
if ($LASTEXITCODE -ne 0) { throw "system stream pipeline tests failed: $LASTEXITCODE" }
& node --test (Join-Path $PSScriptRoot 'mh-stream-ack.test.mjs')
if ($LASTEXITCODE -ne 0) { throw "stream ACK tests failed: $LASTEXITCODE" }
& node --test (Join-Path $PSScriptRoot 'mhgu-packet-transform.test.mjs')
if ($LASTEXITCODE -ne 0) { throw "GU packet transform tests failed: $LASTEXITCODE" }
& node --test (Join-Path $PSScriptRoot 'mh-packet-transform.test.mjs')
if ($LASTEXITCODE -ne 0) { throw "shared packet transform tests failed: $LASTEXITCODE" }
& node --test (Join-Path $PSScriptRoot 'mh-packet.test.mjs')
if ($LASTEXITCODE -ne 0) { throw "packet framing tests failed: $LASTEXITCODE" }
& node --test (Join-Path $PSScriptRoot 'mh-packet-identity.test.mjs')
if ($LASTEXITCODE -ne 0) { throw "packet identity tests failed: $LASTEXITCODE" }
& node --test (Join-Path $PSScriptRoot 'mh-base-peer-list-endpoints.test.mjs')
if ($LASTEXITCODE -ne 0) { throw "base peer list endpoint tests failed: $LASTEXITCODE" }
& node --test (Join-Path $PSScriptRoot 'mh-collection-evidence.test.mjs')
if ($LASTEXITCODE -ne 0) { throw "collection evidence tests failed: $LASTEXITCODE" }
& node --test (Join-Path $PSScriptRoot 'mh-init-raw-observations.test.mjs')
if ($LASTEXITCODE -ne 0) { throw "init raw observations tests failed: $LASTEXITCODE" }
& node --test (Join-Path $PSScriptRoot 'yuzu-udp-proxy.test.mjs')
if ($LASTEXITCODE -ne 0) { throw "Yuzu UDP Proxy tests failed: $LASTEXITCODE" }
& node --test (Join-Path $PSScriptRoot 'yuzu-udp-datagram.test.mjs')
if ($LASTEXITCODE -ne 0) { throw "Yuzu UDP datagram tests failed: $LASTEXITCODE" }
& node --test (Join-Path $PSScriptRoot 'mh-gu-proxy-identity.test.mjs')
if ($LASTEXITCODE -ne 0) { throw "GU Proxy identity composition tests failed: $LASTEXITCODE" }
& node --test (Join-Path $PSScriptRoot 'mh-base-peer-list-stream.test.mjs')
if ($LASTEXITCODE -ne 0) { throw "base peer list stream tests failed: $LASTEXITCODE" }
& node --test (Join-Path $PSScriptRoot 'mh-base-peer-list-stream-sender.test.mjs')
if ($LASTEXITCODE -ne 0) { throw "base peer list sender tests failed: $LASTEXITCODE" }
& node --test (Join-Path $PSScriptRoot 'mh-stream-context-ack.test.mjs')
if ($LASTEXITCODE -ne 0) { throw "context ACK tests failed: $LASTEXITCODE" }
& node --test (Join-Path $PSScriptRoot 'mh-stream-send-replay.test.mjs')
if ($LASTEXITCODE -ne 0) { throw "send window replay tests failed: $LASTEXITCODE" }
& node --test (Join-Path $PSScriptRoot 'mh-stream-receive-preview.test.mjs')
if ($LASTEXITCODE -ne 0) { throw "receive preview tests failed: $LASTEXITCODE" }
& node --test (Join-Path $PSScriptRoot 'mh-stream-receive-sequence.test.mjs')
if ($LASTEXITCODE -ne 0) { throw "receive sequence tests failed: $LASTEXITCODE" }
& node --test (Join-Path $PSScriptRoot 'mh-heartbeat-pair-learn.test.mjs')
& node --test (Join-Path $PSScriptRoot 'mh-kind0-translate.test.mjs')
& node --test (Join-Path $PSScriptRoot 'mh-heartbeat-translate.test.mjs')
& node --test (Join-Path $PSScriptRoot 'mh-control-frame-translate.test.mjs')
if ($LASTEXITCODE -ne 0) { throw "heartbeat pair learner tests failed: $LASTEXITCODE" }
& node --test (Join-Path $PSScriptRoot 'mh-base-peer-list-transfer-preview.test.mjs')
if ($LASTEXITCODE -ne 0) { throw "base peer list transfer preview tests failed: $LASTEXITCODE" }
exit 0
