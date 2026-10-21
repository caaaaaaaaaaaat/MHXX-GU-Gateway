// Offline codec for the six-byte endpoint representation inspected at
// MHXX 1.4 0x00ABD948: BE32 IPv4 followed by BE16 port. This is not a
// claim about its location in every application payload or its transport.

// Local UDS provider at 0x007B465C hashes the eight NodeInfo seed bytes
// with reflected CRC-32/ISO-HDLC (0x008322F8), then uses port 12345.
// The result is a synthetic application endpoint, not a routable host IP.
// Input bytes retain the original u64_le NodeInfo memory order.
export function deriveMhxxUdsEndpoint(seedBytes) {
  if (!Buffer.isBuffer(seedBytes) || seedBytes.length !== 8) {
    throw new TypeError('mhxx_uds_seed_requires_eight_bytes');
  }
  let crc = 0xffffffff;
  for (const byte of seedBytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) {
      crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
    }
  }
  const bytes = Buffer.alloc(6);
  bytes.writeUInt32BE((~crc) >>> 0, 0);
  bytes.writeUInt16BE(12345, 4);
  return decodeMhxxEndpoint(bytes);
}

export function decodeMhxxEndpoint(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length !== 6) {
    throw new TypeError('mhxx_endpoint_requires_six_bytes');
  }
  return {
    address: Array.from(bytes.subarray(0, 4)).join('.'),
    port: bytes.readUInt16BE(4),
  };
}

export function encodeMhxxEndpoint(endpoint) {
  if (!endpoint || typeof endpoint.address !== 'string' ||
      !Number.isInteger(endpoint.port) || endpoint.port < 0 || endpoint.port > 65535) {
    throw new TypeError('invalid_mhxx_endpoint');
  }
  const octets = endpoint.address.split('.');
  if (octets.length !== 4 || octets.some(part =>
    !/^(0|[1-9][0-9]{0,2})$/.test(part) || Number(part) > 255)) {
    throw new TypeError('invalid_mhxx_endpoint_address');
  }
  const bytes = Buffer.alloc(6);
  octets.forEach((part, index) => { bytes[index] = Number(part); });
  bytes.writeUInt16BE(endpoint.port, 4);
  return bytes;
}
