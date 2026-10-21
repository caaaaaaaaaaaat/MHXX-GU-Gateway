"""Minimal GDB Remote Serial Protocol client for the V-282 Citra experiment.

Watches four execution breakpoints inside MHXX's Pia family-02 handler.

Invariant: the game must NEVER be left halted.  Every failure path reconnects,
re-arms and resumes.  Register state comes from a single fast "g" packet per
hit; any failure there logs the hit bare and resumes. WATCH contains VMAs.
"""
import socket
import time

PORT = 24689
VMA_BASE = 0

# 0x7eb7c4 sits in MHXX's per-frame hot loop (~6000 hits/s) — unusable as a
# breakpoint; the three below fire only when a blob is actually received.
WATCH = [
    ("blob-delivery 0x7eb0cc", 0x7EB0CC),
    ("station-state 0x7eb3a4", 0x7EB3A4),
    ("status5-write 0x7eb7f4", 0x7EB7F4),
]

MAX_HITS = 200
REG_CHUNKS = [("r0", 8), ("r4", 8), ("pc", 8)]
LOG = open(".private-runtime/evidence/v282-live/gdb-hits.log", "a", encoding="utf-8")


def log(line):
    stamp = time.strftime("%H:%M:%S")
    print(f"[rsp] {stamp} {line}", flush=True)
    LOG.write(f"{stamp} {line}\n")
    LOG.flush()


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


def arm_all(client):
    for name, offset in WATCH:
        client.cmd(f"Z0,{offset + VMA_BASE:x},1", timeout=2.0)
    log("breakpoints armed")


def resume(client):
    try:
        client.send("c")
    except OSError:
        raise ConnectionError("resume failed")


def read_regs(client):
    """One 'g' packet; returns {r0, r4, pc} with 0 for unparsable fields."""
    out = {"r0": 0, "r4": 0, "pc": 0}
    try:
        reply = client.cmd("g", timeout=2.0)
    except (ConnectionError, TimeoutError, OSError):
        raise
    if not reply or reply[0] in ("T", "E") or reply == "OK":
        return out
    try:
        for name, pos in (("r0", 0), ("r4", 32), ("pc", 120)):
            chunk = reply[pos:pos + 8]
            if len(chunk) == 8:
                out[name] = int.from_bytes(bytes.fromhex(chunk), "little")
    except ValueError:
        pass
    return out


def main():
    deadline = time.time() + 3600
    hits = 0
    run_key = [None, 0]
    while time.time() < deadline:
        log(f"waiting for Citra stub on 127.0.0.1:{PORT} ...")
        try:
            client = Rsp(PORT)
        except OSError:
            time.sleep(0.5)
            continue
        log("connected; arming breakpoints")
        try:
            arm_all(client)
            resume(client)
        except (ConnectionError, TimeoutError, OSError) as err:
            log(f"arm/resume failed ({err}); retrying")
            time.sleep(0.5)
            continue

        halted = False
        while time.time() < deadline:
            try:
                stop = client.recv_packet(timeout=30)
            except TimeoutError:
                continue
            except ConnectionError as err:
                # If we died between a stop and the resume, reconnect and
                # blindly resume so the game cannot stay frozen.
                if halted:
                    log(f"lost while halted ({err}); reconnect to resume")
                    try:
                        fresh = Rsp(PORT)
                        fresh.send("c")
                        log("reconnected and resumed")
                    except OSError:
                        log("game may be halted with no stub client; "
                            "restart Citra if it stays frozen")
                    break
                log(f"connection lost ({err}); will reconnect")
                break
            if not stop.startswith(("T", "S")):
                continue
            halted = True
            hits += 1
            try:
                regs = read_regs(client)
            except (ConnectionError, TimeoutError, OSError) as err:
                log(f"hit#{hits} register read failed ({err})")
                try:
                    resume(client)
                    halted = False
                except ConnectionError:
                    break
                continue
            pc = regs["pc"] & ~1
            name = next((n for n, off in WATCH if off + VMA_BASE == pc),
                        f"pc={pc:#x}")
            key = (name, regs["r4"])
            if name == "status5-write 0x7eb7f4":
                log(f"*** STATUS 5 GRANTED *** r4={regs['r4']:#x} "
                    f"r0={regs['r0']:#x} (hit#{hits})")
                run_key[0] = None
            elif key == run_key[0]:
                run_key[1] += 1
                if run_key[1] % 100 == 0:
                    log(f"hit#{hits} {name} r4={regs['r4']:#x} "
                        f"x{run_key[1]} (repeated, suppressed)")
            else:
                log(f"hit#{hits} {name} r0={regs['r0']:#x} r4={regs['r4']:#x}")
                run_key[0] = key
                run_key[1] = 0
            halted = False
            if hits >= MAX_HITS:
                log("hit cap reached; disarming and resuming")
                for _, off in WATCH:
                    try:
                        client.cmd(f"z0,{off + VMA_BASE:x},1", timeout=2.0)
                    except (ConnectionError, TimeoutError, OSError):
                        pass
                try:
                    resume(client)
                except ConnectionError:
                    pass
                return
            try:
                resume(client)
            except ConnectionError as err:
                log(f"resume failed ({err}); reconnect to resume")
                break
    log("deadline reached; exiting")


if __name__ == "__main__":
    main()
