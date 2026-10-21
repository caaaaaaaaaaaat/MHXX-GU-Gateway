# SPDX-License-Identifier: GPL-2.0-or-later
"""CLI parser regression tests; --help exits before any socket setup.

Run from the workspace root after building the gateway:
  python crossplay/citra-gateway/tests/test_cli.py
Set CITRA_GATEWAY_TEST_EXE to test a different build.
"""
import os
from pathlib import Path
import subprocess
import socket
import tempfile
import unittest


MODULE = Path(__file__).resolve().parents[1]
EXE = Path(os.environ.get('CITRA_GATEWAY_TEST_EXE', str(MODULE / '.build-direct/citra-gateway.exe')))


class ScriptDirectiveCliTests(unittest.TestCase):
    def invoke(self, text):
        # The valid frame is irrelevant to these parser-only checks. A malformed
        # directive must fail before --help; accepted scripts stop at --help.
        with tempfile.TemporaryDirectory(prefix='gateway-cli-') as folder:
            path = Path(folder) / 'input.script'
            path.write_text(text + '\n0 0 bc 00\n', encoding='ascii')
            return subprocess.run([str(EXE), '--game-script', str(path), '--help'],
                                  capture_output=True, text=True, timeout=10)

    def rejected(self, text, diagnostic):
        result = self.invoke(text)
        self.assertEqual(result.returncode, 2, (result.stdout, result.stderr))
        self.assertIn(diagnostic, result.stderr)
        self.assertNotIn('usage: citra-gateway', result.stdout)

    def test_token_keyword_is_not_consumed_as_nonce_argument(self):
        # V-133a: old parser silently ignored this invalid token directive and
        # returned success. Options-only tests never exercised main.cpp.
        self.rejected('# token-ref zz 112:48', "'# token-ref' needs 8 hexadecimal digits")

    def test_invalid_token_after_valid_nonce(self):
        self.rejected('# nonce-ref c9c93d03\n# token-ref zz 112:48',
                      "'# token-ref' needs 8 hexadecimal digits")

    def test_missing_token_value(self):
        self.rejected('# token-ref', "'# token-ref' needs 8 hexadecimal digits")

    def test_missing_learn_site(self):
        self.rejected('# token-ref e4d5c9a7', 'needs at least one')

    def test_learn_site_requires_colon(self):
        self.rejected('# token-ref e4d5c9a7 112', 'learn site must be')

    def test_learn_site_must_fit_four_bytes(self):
        self.rejected('# token-ref e4d5c9a7 112:109', 'learn site must be')

    def test_learn_site_length_limit(self):
        self.rejected('# token-ref e4d5c9a7 65536:48', 'learn site must be')

    def test_learn_site_unsigned_decimal(self):
        self.rejected('# token-ref e4d5c9a7 112:-1', 'learn site must be')

    def test_invalid_nonce(self):
        self.rejected('# nonce-ref zz', "'# nonce-ref' needs 8 hexadecimal digits")

    def test_valid_directives_in_both_orders(self):
        lines = ['# nonce-ref c9c93d03', '# token-ref e4d5c9a7 112:48 268:69']
        for ordered in [lines, list(reversed(lines))]:
            with self.subTest(order=ordered):
                result = self.invoke('\n'.join(ordered))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('usage: citra-gateway', result.stdout)

    def test_last_four_bytes_are_valid_learn_site(self):
        result = self.invoke('# token-ref 01020304 112:108')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_committed_replay_scripts_parse_without_running(self):
        for name in ['mhxx-host-enter.script', 'mhxx-host-enter-long.script']:
            with self.subTest(script=name):
                result = subprocess.run([str(EXE), '--game-script', str(MODULE / 'fixtures' / name), '--help'],
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('usage: citra-gateway', result.stdout)


class LdnProxyPortCliTests(unittest.TestCase):
    def invoke(self, *values):
        # main.cpp parses in argv order: the port must precede --help.
        # Even accidentally accepted invalid inputs stop at --help, not sockets.
        # No values means a genuinely missing argument, without a trailing help.
        args = ['--ldn-proxy-port', *values]
        if values:
            args.append('--help')
        return subprocess.run([str(EXE), *args], capture_output=True,
                              text=True, timeout=10)

    def test_valid_ports_parse_without_running(self):
        for value in ['12345', '1', '65535']:
            with self.subTest(value=value):
                result = self.invoke(value)
                self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
                self.assertIn('usage: citra-gateway', result.stdout)
                self.assertEqual(result.stderr, '')

    def test_invalid_ports_fail_before_help(self):
        for value in ['0', '65536', '-1', '+1', '', ' ', '\t', ' 1', '1 ',
                      '12345junk', '9' * 1000, '18446744073709551617',
                      '１２３４５', '١٢٣٤٥']:
            with self.subTest(value=value):
                result = self.invoke(value)
                self.assertEqual(result.returncode, 2, (result.stdout, result.stderr))
                self.assertIn('--ldn-proxy-port', result.stderr)
                self.assertNotIn('usage: citra-gateway', result.stdout)

    def test_missing_port_value(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 2, (result.stdout, result.stderr))
        self.assertIn('missing value for --ldn-proxy-port', result.stderr)
        self.assertNotIn('usage: citra-gateway', result.stdout)


class GameReturnCliTests(unittest.TestCase):
    def test_missing_return_dependencies_are_usage_errors(self):
        combinations = [
            ['--control-plane', '--ldn-guest-inject', '--ldn-proxy-port', '12345'],
            ['--control-plane', '--ldn-announce-forward', '--ldn-identity-pair',
             'b35ee27f:c0a80101', '--ldn-proxy-port', '12345'],
            ['--control-plane', '--ldn-announce-forward', '--ldn-identity-pair',
             'b35ee27f:c0a80101', '--ldn-guest-inject'],
        ]
        for flags in combinations:
            with self.subTest(flags=flags):
                result = subprocess.run([str(EXE), '--ldn-game-return', *flags],
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 2, (result.stdout, result.stderr))
                self.assertIn('--ldn-game-return requires', result.stderr)

    def test_return_option_is_recognized_before_help(self):
        result = subprocess.run([str(EXE), '--ldn-game-return', '--help'],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('--ldn-game-return', result.stdout)


class GuHostDiscoveryCliTests(unittest.TestCase):
    def test_admission_requires_discovery(self):
        result = subprocess.run([str(EXE), '--ldn-gu-host-admission'],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 2, (result.stdout, result.stderr))
        self.assertIn('--ldn-gu-host-admission requires', result.stderr)

    def test_admission_option_parses_without_startup(self):
        result = subprocess.run([str(EXE), '--ldn-gu-host-admission', '--help'],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('--ldn-gu-host-admission', result.stdout)

    def test_missing_profile_is_rejected_before_startup(self):
        result = subprocess.run([str(EXE), '--control-plane', '--ldn-gu-host-discovery'],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 2, (result.stdout, result.stderr))
        self.assertIn('--ldn-gu-host-discovery requires', result.stderr)

    def test_discovery_option_parses_without_startup(self):
        result = subprocess.run([str(EXE), '--ldn-gu-host-discovery', '--help'],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('discovery only', result.stdout)


class DualHostCliTests(unittest.TestCase):
    def test_dual_mode_help(self):
        result = subprocess.run([str(EXE), '--ldn-dual-host', '--help'],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('--ldn-dual-host', result.stdout)

    def test_dual_mode_requires_profile_and_port(self):
        for flags in [[], ['--control-plane'],
                      ['--control-plane', '--uds-profile', 'mhxx',
                       '--ldn-comm-id', '0100770008dd8000']]:
            with self.subTest(flags=flags):
                result = subprocess.run([str(EXE), '--ldn-dual-host', *flags],
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn('--ldn-dual-host requires', result.stderr)

    def test_complete_dual_mode_starts_without_static_identity_pairs(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.bind(('127.0.0.1', 0))
            listen_port = str(probe.getsockname()[1])
        result = subprocess.run([str(EXE), '--ldn-dual-host', '--control-plane',
                                 '--uds-profile', 'mhxx', '--ldn-comm-id', '0100770008dd8000',
                                 '--ldn-proxy-port', '12345', '--listen-port', listen_port, '--seconds', '0'],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
        self.assertIn('gateway listening', result.stdout)

    def test_legacy_mixed_roles_still_require_explicit_dual_mode(self):
        result = subprocess.run([str(EXE), '--control-plane', '--ldn-gu-host-discovery',
                                 '--uds-profile', 'mhxx', '--ldn-comm-id', '0100770008dd8000',
                                 '--ldn-require-live-hall'], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn('excludes Citra-host options', result.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
