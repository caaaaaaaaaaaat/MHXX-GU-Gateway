import json
p = 'G:/mh-evidence/g2-trace/g2a-20261015T083801-local-gwA.jsonl'
shown = 0
with open(p, encoding='utf-8') as f:
    for line in f:
        try: r = json.loads(line)
        except: continue
        if r.get('structure') != 'citra_secure_data' or not r.get('raw_hex'): continue
        payload = bytes.fromhex(r['raw_hex'])
        if abs(len(payload) - 390) > 8: continue
        magic = payload.find(bytes.fromhex('32ab9864'))
        llc = payload.find(bytes.fromhex('aaaa03000000876d'))
        print('len:', len(payload), 'magic_at:', magic, 'llc_at:', llc)
        print('bytes 0x00..0x40:')
        for off in range(0, 0x40, 16):
            print(f'  {off:02x}: {payload[off:off+16].hex()}')
        shown += 1
        if shown >= 2: break
