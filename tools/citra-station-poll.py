"""Passive station-manager poller for the V-282 Citra experiment.

Reads MHXX's Pia station manager over the GDB stub while the game RUNS
(memory reads without breakpoints; snapshots can miss short transitions).

The Citra stub may accept only one connection per initialization. Keep a
working observer alive: replacing it mid-session can lose the observation
channel until the user starts a fresh emulator session.

Handler global VA 0xd410e4. The lookup at 0x7e8344 uses count u32 at
object+0x38 and inline station pointers at object+0x3c. Each station has
endpoint word at +8, tag at +0x10 and status at +0x20. The separate global
0xd613b8 owns descriptor pairs, not station records; never read their
offset +0x20 as a station status.

Logs every change of (count, per-record word/status) so the guest station's
status trajectory around the join attempt is visible.
"""
import argparse
from pathlib import Path
import socket
import time

PORT = 24689
MGR = 0xD410E4
DEADLINE = 3600
POLL = 0.2
STREAM_WRAPPER = 0xD410E8  # V294: literal at 0x7f1a94
GAME_MANAGER = 0xD3F634  # V295: literal at 0x841710
SESSION_MANAGER = 0xD3EFD8  # V297: literal at 0x9acf98


class Rsp:
    def __init__(self, port):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        self.sock.settimeout(1.0)
        self.buf = b""

    def send(self, body):
        csum = sum(body.encode()) & 0xFF
        self.sock.sendall(f"${body}#{csum:02x}".encode())

    def recv_packet(self, timeout=3.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            start = self.buf.find(b"$")
            end = self.buf.find(b"#", start + 1)
            if start != -1 and end != -1 and len(self.buf) >= end + 3:
                body = self.buf[start + 1:end].decode(errors="replace")
                self.buf = self.buf[end + 3:]
                self.sock.sendall(b"+")
                return body
            try:
                data = self.sock.recv(4096)
            except socket.timeout:
                continue
            if not data:
                raise ConnectionError("stub closed")
            self.buf += data
        raise TimeoutError("no packet")

    def cmd(self, body, timeout=2.0):
        self.send(body)
        return self.recv_packet(timeout)

    def read_mem(self, addr, length):
        reply = self.cmd(f"m{addr:x},{length:x}")
        if not reply or reply[0] in ("T", "E") or reply == "OK":
            return None
        try:
            data = bytes.fromhex(reply)
            return data if len(data) == length else None
        except ValueError:
            return None


def u32(client, addr):
    mem = client.read_mem(addr, 4)
    if not mem or len(mem) < 4:
        return None
    return int.from_bytes(mem, "little")


def stream_snapshot(client):
    """Bounded passive reads; fields retain offsets where semantics are unknown."""
    def pointer(value):
        return value is not None and 0x100000 <= value < 0x40000000 and value % 4 == 0

    wrapper = u32(client, STREAM_WRAPPER)
    if not pointer(wrapper):
        return f"stream_wrapper={wrapper} (null/unreadable/out of range)"
    data = client.read_mem(wrapper, 0x14)
    if data is None:
        return f"stream_wrapper={wrapper:#x} unreadable"
    worker = int.from_bytes(data[0x10:0x14], "little")
    if not pointer(worker):
        return f"stream_wrapper={wrapper:#x} worker={worker} (null/out of range)"
    data = client.read_mem(worker, 0x90)
    if data is None:
        return f"stream_wrapper={wrapper:#x} worker={worker:#x} unreadable"
    word = lambda offset: int.from_bytes(data[offset:offset+4], "little")
    interface, backing = word(0x80), word(0x1c)
    vptr = u32(client, interface) if pointer(interface) else None
    producer_cursor = u32(client, backing+0xc) if pointer(backing) else None
    # +28 is a held-view count; zero can still acquire a fresh ring buffer.
    # These are non-atomic observations and cannot establish queue starvation.
    return (f"stream_wrapper={wrapper:#x} worker={worker:#x} "
            f"worker_vptr={word(0):#x} thread={word(0x40):#x} "
            f"state58={data[0x58]} interface={interface:#x} interface_vptr={vptr} "
            f"ring={backing:#x} view20={word(0x20)} view24={word(0x24)} "
            f"view28={word(0x28)} backing0c={producer_cursor} processed84={word(0x84)}")


def game_protocol_snapshot(client):
    """V296: read only the pinned game's unreliable protocol metadata."""
    def pointer(value):
        return value is not None and 0x100000 <= value < 0x40000000 and value % 4 == 0

    manager = u32(client, GAME_MANAGER)
    if not pointer(manager):
        return f"game_manager={manager} (null/unreadable/out of range)"
    game = u32(client, manager + 0x24)
    if not pointer(game):
        return f"game_manager={manager:#x} game={game} (null/unreadable/out of range)"
    protocol = u32(client, game + 0x30864)
    if not pointer(protocol):
        return f"game={game:#x} protocol={protocol} (null/unreadable/out of range)"
    data = client.read_mem(protocol, 0x20)
    if data is None:
        return f"game={game:#x} protocol={protocol:#x} unreadable"
    word = lambda offset: int.from_bytes(data[offset:offset+4], "little")
    # +18 points to the receive backlog, not the game send queue.
    backlog = word(0x18)
    count = u32(client, backlog + 0xc) if pointer(backlog) else None
    return (f"game={game:#x} protocol={protocol:#x} protocol_vptr={word(0):#x} "
            f"protocol_id={word(0xc):08x} active_tag={data[0x1c]:02x} "
            f"transport={word(0x10):#x} receive_backlog={backlog:#x} receive_count={count}")


def game_events_snapshot(client):
    """Read bounded local connection-event metadata, never peer payloads.

    Sampling can miss events drained between reads; a zero queue is not
    proof that no event was emitted. Error50 is reported without inferring
    the branch that set it. This function performs no writes or breakpoints.
    """
    def pointer(value):
        return value is not None and 0x100000 <= value < 0x40000000 and value % 4 == 0

    manager = u32(client, GAME_MANAGER)
    if not pointer(manager):
        return f"events_manager={manager} (null/unreadable/out of range)"
    game = u32(client, manager + 0x24)
    if not pointer(game):
        return f"events_game={game} (null/unreadable/out of range)"
    header = client.read_mem(game + 0x30850, 0x1c)
    if header is None or len(header) != 0x1c:
        return f"events_game={game:#x} header unreadable"
    count = int.from_bytes(header[0x18:0x1c], 'little', signed=True)
    fields = [f"events_game={game:#x} event_error50={header[0]} event_count={count}"]
    config = client.read_mem(game + 0x2ad78, 8)
    if config is not None and len(config) == 8:
        fields.append(f"metadata_config78={int.from_bytes(config[:4], 'little', signed=True)} metadata_config7c={int.from_bytes(config[4:], 'little', signed=True)}")
    if not 0 <= count <= 16:
        fields.append("event entries skipped (count out of range)")
    elif count:
        entries = client.read_mem(game + 0x3086c, count * 8)
        if entries is None or len(entries) != count * 8:
            fields.append("event entries unreadable")
        else:
            for index in range(count):
                entry = entries[index*8:(index+1)*8]
                fields.append(f"event{index}[tag={entry[0]:02x} kind={int.from_bytes(entry[4:8], 'little')}]")
    return ' '.join(fields)


def station_connection_snapshot(client, station):
    """V297: bounded metadata from station+24, not station+30's interface.

    Require the pinned connection vptr before interpreting fields. Never
    follow queue backing pointers or infer admission from a sampled state.
    """
    if station is None or len(station) < 0x28:
        return 'admission[station unreadable]'
    connection = int.from_bytes(station[0x24:0x28], 'little')
    if not 0x100000 <= connection <= 0x40000000 - 0x20 or connection % 4:
        return f'admission[ptr={connection:#x} out of range]'
    data = client.read_mem(connection, 0x20)
    if data is None or len(data) != 0x20:
        return f'admission[ptr={connection:#x} unreadable]'
    word = lambda offset: int.from_bytes(data[offset:offset+4], 'little')
    if word(0) != 0xD05F68:
        return f'admission[ptr={connection:#x} unexpected_vptr={word(0):#x}]'
    return (f'admission[ptr={connection:#x} id={word(4):08x} '
            f'local={data[8]:02x} remote={data[9]:02x} '
            f'tx_backing={word(0xc):#x} tx_capacity={word(0x10)} '
            f'tx_queued={word(0x1c)}]')


def notification_snapshot(client):
    """Report raw notification gates; separate reads can race with teardown."""
    def pointer(value, extent):
        return value is not None and 0x100000 <= value <= 0x40000000 - extent and value % 4 == 0

    fields = [f'admission_sentinel={u32(client, 0xD61390)}']
    group = u32(client, 0xD410EC)
    if pointer(group, 0x29):
        active = client.read_mem(group + 0x28, 1)
        fields.append(f'module_active={active[0] if active and len(active) == 1 else None}')
    else:
        fields.append(f'module_manager={group} (out of range)')
    session = u32(client, 0xD613C8)
    if pointer(session, 0xac):
        fields.append(f'notification_mask={u32(client, session + 0x70)}')
        fields.append(f'notification_handler={u32(client, session + 0xa8)}')
    else:
        fields.append(f'notification_session={session} (out of range)')
    return ' '.join(fields)


def descriptor_identity_snapshot(client):
    """V300: bounded registry/station identity reads; never read payloads."""
    def pointer(value, size):
        return value is not None and 0x100000 <= value <= 0x40000000 - size and value % 4 == 0

    registry = u32(client, 0xD613B8)
    if not pointer(registry, 0x11c):
        return 'descriptor_registry[invalid]'
    header = client.read_mem(registry + 0xe4, 0x38)
    if header is None or len(header) != 0x38:
        return 'descriptor_registry[unreadable]'
    backing = int.from_bytes(header[:4], 'little')
    count = int.from_bytes(header[0x34:0x38], 'little')
    if count > 12 or not pointer(backing, count * 0x68):
        return f'descriptor_registry[invalid count={count}]'
    fields = []
    for index in range(count):
        station = int.from_bytes(header[4 + index*4:8 + index*4], 'little')
        if not station:
            continue
        if not pointer(station, 0x20):
            fields.append(f'descriptor_id[{index}:invalid station]')
            continue
        descriptor = client.read_mem(backing + index*0x68, 0x20)
        current = client.read_mem(station + 0x18, 8)
        if descriptor is None or len(descriptor) != 0x20 or current is None or len(current) != 8:
            fields.append(f'descriptor_id[{index}:unreadable]')
            continue
        value = int.from_bytes(descriptor[0x18:0x20], 'little')
        active = int.from_bytes(current, 'little')
        fields.append(f'descriptor_id[station={station:#x} id={value:016x} station_id={active:016x}]')
    return ' '.join(fields) if fields else f'descriptor_registry[count={count} empty]'


def event_bridge_snapshot(client):
    """Bounded callback/list/cache metadata; no payload or backing reads.

    Notification B records an attempted callback, not game acceptance.
    Sampling may miss short-lived records and is not an execution trace.
    """
    def pointer(value, size):
        return value is not None and 0x100000 <= value <= 0x40000000 - size and value % 4 == 0

    fields = []
    owner = u32(client, 0xD410F8)
    if pointer(owner, 0x88):
        header = client.read_mem(owner + 0x58, 0x30)
        if header is None or len(header) != 0x30:
            fields.append('event_bridge[owner unreadable]')
        else:
            word = lambda offset: int.from_bytes(header[offset:offset+4], 'little')
            fields.append(f'event_bridge[owner={owner:#x} callback={word(0):#x} context={word(4):#x}]')
            listing = word(0xc)
            if pointer(listing, 0x10):
                first = u32(client, listing + 0xc)
                current, visited = first, set()
                sentinel = listing + 8
                while current != sentinel and len(visited) < 12:
                    if not pointer(current, 0x18) or current in visited:
                        fields.append(f'notify_nodes[invalid_or_cycle={current}]')
                        break
                    visited.add(current)
                    node = client.read_mem(current, 0x18)
                    if node is None or len(node) != 0x18:
                        fields.append('notify_nodes[unreadable]')
                        break
                    identity = int.from_bytes(node[0x10:0x18], 'little')
                    fields.append(f'notify_node[id={identity:016x} A={node[0xa]} B={node[0xb]}]')
                    current = int.from_bytes(node[4:8], 'little')
                if len(visited) == 12 and current != sentinel:
                    fields.append('notify_nodes[limit=12]')
            else:
                fields.append(f'notify_list={listing} (out of range)')
    else:
        fields.append(f'event_bridge_owner={owner} (out of range)')
    manager = u32(client, GAME_MANAGER)
    game = u32(client, manager + 0x24) if pointer(manager, 0x28) else None
    if pointer(game, 0x2adf0):
        cache = client.read_mem(game + 0x2ad90, 96)
        if cache is None or len(cache) != 96:
            fields.append('event_identity_cache[unreadable]')
        else:
            entries = [f'{index}:{int.from_bytes(cache[index*8:index*8+8], "little"):016x}'
                       for index in range(12) if any(cache[index*8:index*8+8])]
            fields.append('event_identity_cache[' + ','.join(entries) + ']')
    else:
        fields.append(f'event_cache_game={game} (out of range)')
    return ' '.join(fields)


def frontend_snapshot(client):
    """V297: locate one pinned frontend in four registered child slots.

    Reads metadata only, never the queued application payload. The protocol
    and frontend objects are different; no station state is inferred here.
    """
    def pointer(value):
        return value is not None and 0x100000 <= value < 0x40000000 and value % 4 == 0

    manager = u32(client, SESSION_MANAGER)
    if not pointer(manager):
        return f"session_manager={manager} (null/unreadable/out of range)"
    parent = u32(client, manager + 0x30)
    if not pointer(parent):
        return f"session_manager={manager:#x} parent={parent} (null/unreadable/out of range)"
    children = client.read_mem(parent + 0x74, 0x10)
    if children is None:
        return f"session_parent={parent:#x} children unreadable"
    matches = []
    for offset in range(0,0x10,4):
        child = int.from_bytes(children[offset:offset+4], 'little')
        if pointer(child) and u32(client, child) == 0xD07160:
            matches.append(child)
    matches = sorted(set(matches))
    if len(matches) != 1:
        return f"session_parent={parent:#x} frontend_matches={len(matches)} (need exactly one)"
    frontend = matches[0]
    threads = client.read_mem(frontend + 0x80, 8)
    peers = client.read_mem(frontend + 0x514, 4*0xc)
    if threads is None or peers is None:
        return f"frontend={frontend:#x} metadata unreadable"
    sender = int.from_bytes(threads[:4], 'little')
    fields = [f"frontend={frontend:#x} game_sender={sender:#x}"]
    for index in range(4):
        peer = peers[index*0xc:(index+1)*0xc]
        send_slot = int.from_bytes(peer[4:8],'little',signed=True)
        recv_slot = int.from_bytes(peer[8:12],'little',signed=True)
        fields.append(f"peer{index}[allocated={peer[0]} connected={peer[1]} send_slot={send_slot} recv_slot={recv_slot}]")
    if pointer(sender):
        sender_vptr = u32(client,sender)
        fields.append(f"game_sender_vptr={sender_vptr}")
        if sender_vptr != 0xD0713C:
            fields.append("sender metadata skipped (unexpected/unreadable vptr)")
            return ' '.join(fields)
        active = client.read_mem(sender+0x7c,1)
        error = client.read_mem(sender+0x509,7)
        fields.append(f"sender_active={active[0] if active else None}")
        if error is not None:
            fields.append(f"sender_error={error[0]} sender_result={int.from_bytes(error[3:7],'little'):08x}")
        for index in range(4):
            entry = sender + 0x510 + index*0x808
            tag = client.read_mem(entry,1)
            count = u32(client,entry+0x804)
            fields.append(f"send{index}[tag={tag[0] if tag else None} bytes={count}]")
    return ' '.join(fields)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stream-worker", action="store_true",
                        help="also observe the V294 stream wrapper/worker (passive, no breakpoints)")
    parser.add_argument("--game-protocol", action="store_true",
                        help="also read V296 game protocol metadata (passive, no breakpoints)")
    parser.add_argument("--frontend", action="store_true",
                        help="also read V297 game frontend connection and send queue metadata")
    parser.add_argument("--game-events", action="store_true",
                        help="also read bounded game connection-event metadata and error flag")
    parser.add_argument("--log", type=Path,
                        default=Path(".private-runtime/evidence/v282-live/station-poll.log"))
    parser.add_argument("--seconds", type=int, default=DEADLINE)
    args = parser.parse_args()
    if args.seconds <= 0:
        parser.error("--seconds must be positive")
    deadline = time.time() + args.seconds
    logf = open(args.log, "a", encoding="utf-8")

    def log(line):
        stamp = time.strftime("%H:%M:%S")
        print(f"[poll] {stamp} {line}", flush=True)
        logf.write(f"{stamp} {line}\n")
        logf.flush()

    log(f"waiting for Citra stub on 127.0.0.1:{PORT} ...")
    client = None
    while client is None and time.time() < deadline:
        try:
            client = Rsp(PORT)
        except OSError:
            time.sleep(0.5)
    if client is None:
        log("stub never opened; exiting")
        return
    # The stub halts the booting game: resume it immediately.
    try:
        client.send("c")
        log("connected; game resumed (no breakpoints — passive polling)")
    except OSError as err:
        log(f"resume failed: {err}; exiting")
        return

    last = None
    while time.time() < deadline:
      try:
        mgr = u32(client, MGR)
        snapshot = f"mgr={mgr:#x}" if mgr else ("mgr null (not initialized)" if mgr == 0 else "mgr unreadable")
        states = []
        if mgr:
            count = u32(client, mgr + 0x38)
            snapshot += f" count={count}"
            if count is not None and 0 <= count <= 12:
                for i in range(count):
                    rec = u32(client, mgr + 0x3C + i * 4)
                    if not rec:
                        states.append(f"slot{i}[ptr={rec}]")
                        continue
                    # Read one record together to reduce skew while the game runs.
                    data = client.read_mem(rec, 0x6C)
                    if data is None or len(data) != 0x6c:
                        states.append(f"slot{i}[ptr={rec:#x} unreadable]")
                        continue
                    states.append(
                        f"slot{i}[ptr={rec:#x} {data[8:12].hex()} "
                        f"tag={data[0x10]:02x} st={data[0x20]} "
                        f"subtype={data[0x55]:02x} "
                        f"conn={int.from_bytes(data[0x30:0x34], 'little'):#x} "
                        f"job={int.from_bytes(data[0x38:0x3c], 'little'):#x}]")
                    if args.game_events:
                        states.append(station_connection_snapshot(client, data))
            snapshot += " " + " ".join(states)
        if args.stream_worker:
            snapshot += " " + stream_snapshot(client)
        if args.game_protocol:
            snapshot += " " + game_protocol_snapshot(client)
        if args.frontend:
            snapshot += " " + frontend_snapshot(client)
        if args.game_events:
            snapshot += " " + game_events_snapshot(client)
            snapshot += " " + notification_snapshot(client)
            snapshot += " " + event_bridge_snapshot(client)
            snapshot += " " + descriptor_identity_snapshot(client)
        if snapshot != last:
            log(snapshot)
            last = snapshot
      except (ConnectionError, TimeoutError, OSError) as err:
        log(f"stub read unavailable ({type(err).__name__}: {err}); waiting for a usable connection")
        last = None
        if client is not None:
            try:
                client.send("c")
            except OSError:
                pass
            client.sock.close()
        client = None
        while client is None and time.time() < deadline:
            try:
                client = Rsp(PORT)
                client.send("c")
                log("reconnected; passive polling resumed")
            except OSError:
                if client is not None:
                    client.sock.close()
                    client = None
                time.sleep(0.5)
      time.sleep(POLL)
    if client is not None:
        try:
            client.send("c")
        except OSError:
            pass
        client.sock.close()
    logf.close()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
