#!/usr/bin/env python3
"""An internet in a box: real daemons behind real kernel NAT, with no root.

Run through scripts/lab.sh, inside fresh user, network, mount and pid
namespaces. Nothing here can reach the real network or see a process outside
the lab, which is how to test what takes more devices and networks than
there are to hand. Every link has a delay (LAB_DELAY_MS), because with none
each pair of packets crosses at once and no hole can be punched.

    internet ── ana-home  (router, UDP 7171 forwarded to ana-host)
             ├─ dan-home  (strict router, UDP 7171 forwarded to the nuc)
             ├─ cousin-home (no host; or behind carrier-grade NAT)
             ├─ bo-home   (router, UDP 7171 forwarded to bo-host)
             ├─ cafe      (router, no forward)
             ├─ dan-home  (`mapped`: a strict router that answers PCP, no forward)
             ├─ airport   (router, no forward)
             └─ carrier ── tower (a second NAT: carrier-grade NAT)
"""

import json
import os
import shutil
import socket
import statistics
import struct
import subprocess
import sys
import threading
import time

BIN, WORK = sys.argv[1], sys.argv[2]
WHICH = sys.argv[3:] or ["punch", "people"]
SOCKETS = "/run/lab"
DELAY = int(os.environ.get("LAB_DELAY_MS", "15"))


def sh(cmd, check=True, stdin=None):
    r = subprocess.run(cmd, shell=True, input=stdin, text=True, capture_output=True)
    if check and r.returncode != 0:
        raise SystemExit(f"failed: {cmd}\n{r.stdout}{r.stderr}")
    return r.stdout


def wait(what, secs, ok):
    start = time.monotonic()
    while time.monotonic() - start < secs:
        v = ok()
        if v:
            return time.monotonic() - start
        time.sleep(0.25)
    return None


class Net:
    """Namespaces, and the wires between them."""

    def __init__(self):
        self.wire = 0
        self.routers = {}
        self.netns("internet")
        self.forward("internet")

    def netns(self, name):
        sh(f"ip netns add {name}")
        sh(f"ip -n {name} link set lo up")

    def forward(self, name):
        sh(f"ip netns exec {name} sysctl -qw net.ipv4.ip_forward=1")
        sh(f"ip netns exec {name} sysctl -qw net.ipv4.conf.all.rp_filter=0")

    def connect(self, a, a_if, a_addr, b, b_if, b_addr):
        self.wire += 1
        x, y = f"w{self.wire}a", f"w{self.wire}b"
        sh(f"ip link add {x} netns {a} type veth peer name {y} netns {b}")
        sh(f"ip -n {a} link set {x} name {a_if}")
        sh(f"ip -n {b} link set {y} name {b_if}")
        sh(f"ip -n {a} addr add {a_addr} dev {a_if}")
        sh(f"ip -n {b} addr add {b_addr} dev {b_if}")
        sh(f"ip -n {a} link set {a_if} up")
        sh(f"ip -n {b} link set {b_if} up")

    def router(self, name, up, up_ip, up_gw, net, nat, forward=None, up_if=None):
        """A home router. `nat` is easy (keeps ports, as a Linux or OpenWrt
        router does) or hard (a new port per destination, as pfSense does).
        """
        self.netns(name)
        self.forward(name)
        self.wire += 1
        if_up = up_if or f"to-{name}"[:15]
        self.connect(up, if_up, f"{up_gw}/24", name, "wan", f"{up_ip}/24")
        sh(f"ip -n {name} route add default via {up_gw}")
        # Sites are not next door: without this every packet crosses in the
        # same instant, which a real network does not do.
        sh(f"ip netns exec {name} tc qdisc add dev wan root netem delay {DELAY}ms")
        sh(f"ip netns exec {up} tc qdisc add dev {if_up} root netem delay {DELAY}ms")
        sh(f"ip -n {name} link add lan type bridge")
        sh(f"ip -n {name} addr add {net}.1/24 dev lan")
        sh(f"ip -n {name} link set lan up")
        how = "masquerade" if nat == "easy" else "masquerade random,fully-random"
        dnat = ""
        if forward:
            dnat = f'iifname "wan" udp dport 7171 dnat to {forward}:7171'
        sh(
            f"ip netns exec {name} nft -f -",
            stdin=f"""
table ip nat {{
  chain pre {{
    type nat hook prerouting priority -100;
    {dnat}
  }}
  chain post {{
    type nat hook postrouting priority 100;
    oifname "wan" {how}
  }}
}}
table ip filter {{
  chain through {{
    type filter hook forward priority 0; policy drop;
    ct state established,related accept
    iifname "lan" accept
    ct status dnat accept
  }}
}}
""",
        )
        self.routers[name] = net
        return name

    def plug(self, dev, router, last):
        """Gives a device a port on a router's LAN."""
        sh(f"ip -n {dev} link del eth0", check=False)
        net = self.routers[router]
        self.wire += 1
        side = f"p{self.wire}"
        self.connect(dev, "eth0", f"{net}.{last}/24", router, side, f"169.254.0.{self.wire}/32")
        sh(f"ip -n {router} addr flush dev {side}")
        sh(f"ip -n {router} link set {side} master lan")
        sh(f"ip -n {dev} route add default via {net}.1")
        return f"{net}.{last}"


class Dev:
    def __init__(self, net, name, router, last):
        self.net, self.name, self.ns = net, name, f"d-{name}"
        self.home = f"{WORK}/{name}"
        shutil.rmtree(self.home, ignore_errors=True)
        os.makedirs(self.home)
        net.netns(self.ns)
        self.ip = net.plug(self.ns, router, last)
        self.env = dict(
            os.environ,
            CARDINAL_HOME=self.home,
            CARDINAL_SOCKET=f"{SOCKETS}/{name}.sock",
            CARDINAL_LOG="info,cardinald=debug",
            CARDINAL_TEST_POWER_SUPPLIES="/nothing/here",
        )
        self.child = None

    def start(self):
        log = open(f"{self.home}/daemon.log", "ab")
        self.child = subprocess.Popen(
            ["ip", "netns", "exec", self.ns, BIN, "daemon", "--no-discovery", "--no-mount"]
            + ["--name", self.name, "--listen", "0.0.0.0:7171"],
            env=self.env,
            stdout=log,
            stderr=log,
        )
        if wait("up", 15, lambda: self.run("status").returncode == 0) is None:
            raise SystemExit(f"{self.name} did not start:\n{self.log()[-2000:]}")

    def stop(self):
        self.run("stop")
        if self.child:
            try:
                self.child.wait(10)
            except subprocess.TimeoutExpired:
                self.child.kill()
        self.child = None

    def run(self, *args):
        return subprocess.run([BIN, *args], env=self.env, text=True, capture_output=True)

    def cli(self, *args):
        r = self.run(*args)
        if r.returncode != 0:
            raise SystemExit(f"{self.name}: {' '.join(args)}: {r.stdout}{r.stderr}")
        return r.stdout

    def status(self):
        return json.loads(self.cli("status", "--json"))

    def ask(self, req):
        """One request over the local interface, as a window makes it."""
        with socket.socket(socket.AF_UNIX) as s:
            s.settimeout(30)
            s.connect(self.env["CARDINAL_SOCKET"])
            s.sendall((json.dumps(req) + "\n").encode())
            return json.loads(s.makefile().readline())

    def contact(self):
        """The one contact this device has, as it lists them."""
        listed = self.ask({"cmd": "contacts"}).get("contacts") or [{}]
        return listed[0]

    def call_state(self):
        return (self.ask({"cmd": "call"}).get("call") or {}).get("state")

    def log(self):
        with open(f"{self.home}/daemon.log", errors="replace") as f:
            return f.read()

    def seen(self, other):
        for d in self.status()["devices"]:
            if d.get("name") == other:
                return d
        return None

    def online(self, other):
        d = self.seen(other)
        return bool(d and d.get("online"))

    def roam(self, router, last):
        self.ip = self.net.plug(self.ns, router, last)


def pair(a, b):
    p = subprocess.Popen([BIN, "pair"], env=b.env, stdout=subprocess.PIPE, text=True)
    code, port = None, None
    while code is None or port is None:
        line = p.stdout.readline()
        if not line:
            raise SystemExit(f"pair on {b.name} ended early")
        line = line.strip()
        if line.startswith("cardinal pair "):
            code = line.split()[2]
        if "--at " in line:
            at = line[line.index("--at ") + 5:].split()[0]
            port = at.rstrip(".,)`").rsplit(":", 1)[1]
    a.cli("pair", code, "--at", f"{b.ip}:{port}")
    p.wait(30)


def path(d):
    """What a status line says about how a device is reached."""
    if not d or not d.get("online"):
        return "offline"
    if d.get("through"):
        return f"relayed through {d['through']}"
    return f"direct at {d.get('addr')} over {d.get('carrier') or d.get('transport') or '?'}"


def punch(nat_a, nat_b, label, trace=False):
    """Two of a person's devices, each behind its own NAT, with a host
    elsewhere. The first time this has been possible to try."""
    net = Net()
    net.router("ana-home", "internet", "198.51.100.10", "198.51.100.1", "192.168.1", "hard",
               forward="192.168.1.2")
    net.router("cafe", "internet", "198.51.102.10", "198.51.102.1", "192.168.3", nat_a)
    if nat_b == "cgnat":
        net.router("carrier", "internet", "198.51.104.10", "198.51.104.1", "100.64.0", "easy")
        net.router("airport", "carrier", "100.64.1.10", "100.64.1.1", "192.168.4", "easy",
                   up_if="to-airport")
        # The carrier's subscribers come in on this port, not on its LAN.
        sh("ip netns exec carrier nft add rule ip filter through "
           'iifname "to-airport" accept')
    else:
        net.router("airport", "internet", "198.51.103.10", "198.51.103.1", "192.168.4", nat_b)

    host = Dev(net, "host", "ana-home", 2)
    laptop = Dev(net, "laptop", "ana-home", 3)
    phone = Dev(net, "phone", "ana-home", 4)
    host.start()
    host.cli("init", "--yes", "--name", "host")
    laptop.start()
    pair(host, laptop)
    phone.start()
    pair(host, phone)
    host.cli("host", "--address", "198.51.100.10:7171")
    wait("paired", 30, lambda: laptop.online("phone") and phone.online("laptop"))
    wait("settled", 10, lambda: False)

    captures = []
    if trace:
        for name in ("cafe", "airport"):
            out = f"{WORK}/{name}.pcap.txt"
            captures.append((name, out, subprocess.Popen(
                f"exec ip netns exec {name} tcpdump -lnn -i wan -Z root udp > {out} 2>&1",
                shell=True)))

    laptop.roam("cafe", 3)
    phone.roam("airport", 4)

    def away(a, other):
        """Reached by a path that does not depend on the old LAN. A session
        over the old path looks fine until it has gone quiet for 30 s."""
        d = a.seen(other)
        return bool(d and d.get("online") and not (d.get("addr") or "").startswith("192.168.1."))

    both = lambda: away(laptop, "phone") and away(phone, "laptop")
    to_host = wait("to host", 120, lambda: away(laptop, "host") and away(phone, "host"))
    meet = wait("meet", 120, both)
    direct = lambda: both() and not laptop.seen("phone").get("through") \
        and not phone.seen("laptop").get("through")
    went_direct = wait("direct", 45, direct)
    a, b = laptop.seen("phone"), phone.seen("laptop")
    print(f"{label}:", flush=True)
    print(f"    host reached in {to_host and round(to_host)} s, each other in "
          f"{meet and round(meet)} s more, direct: "
          f"{'no, after 45 s more' if went_direct is None else 'yes'}", flush=True)
    print(f"    laptop sees phone: {path(a)}", flush=True)
    print(f"    phone sees laptop: {path(b)}", flush=True)
    print(f"    laptop sees host:  {path(laptop.seen('host'))}", flush=True)
    for name, out, p in captures:
        try:
            p.terminate()
        except PermissionError:
            pass  # It goes when the lab does.
        lines = [l for l in open(out, errors="replace") if " IP " in l]
        pairs = {}
        for l in lines:
            parts = l.split()
            flow = f"{parts[2]} > {parts[4].rstrip(':')}"
            pairs[flow] = pairs.get(flow, 0) + 1
        print(f"    packets on {name}'s WAN:", flush=True)
        for flow, n in sorted(pairs.items(), key=lambda x: -x[1])[:10]:
            print(f"      {n:5} {flow}", flush=True)
    logged = laptop.log().splitlines()
    hints = [l for l in logged if any(w in l.lower() for w in ("punch", "meet", "relay"))]
    for line in hints[-4:]:
        print("    log:", line[-110:], flush=True)
    for d in (laptop, phone, host):
        d.stop()
    sh("for n in $(ip netns list | cut -d' ' -f1); do ip netns del $n; done", check=False)
    return a


def people():
    """Two people, each with a host and a laptop, through hosts only."""
    net = Net()
    net.router("ana-home", "internet", "198.51.100.10", "198.51.100.1", "192.168.1", "hard",
               forward="192.168.1.2")
    net.router("bo-home", "internet", "198.51.101.10", "198.51.101.1", "192.168.2", "easy",
               forward="192.168.2.2")
    net.router("cafe", "internet", "198.51.102.10", "198.51.102.1", "192.168.3", "hard")

    ana_host, ana = Dev(net, "ana-host", "ana-home", 2), Dev(net, "ana", "ana-home", 3)
    bo_host, bo = Dev(net, "bo-host", "bo-home", 2), Dev(net, "bo", "bo-home", 3)
    ana_host.start()
    ana_host.cli("init", "--yes", "--name", "ana-host")
    ana.start()
    pair(ana_host, ana)
    ana_host.cli("host", "--address", "198.51.100.10:7171")
    bo_host.start()
    bo_host.cli("init", "--yes", "--name", "bo-host")
    bo.start()
    pair(bo_host, bo)
    bo_host.cli("host", "--address", "198.51.101.10:7171")
    wait("paired", 30, lambda: ana.online("ana-host") and bo.online("bo-host"))

    code = ana_host.cli("invite", "--address", "198.51.100.10:7171", "--name", "Ana",
                        "--hosts-only").strip()
    print("accept:", bo_host.cli("accept", code, "--hosts-only", "--name", "Ana").strip())
    got = wait("ana lists bo", 30, lambda: "bo" in ana_host.cli("contacts"))
    print(f"ana's host lists bo after {got and round(got, 1)} s")
    told = wait("ana's laptop hears of bo", 30, lambda: "bo" in ana.cli("contacts"))
    print(f"ana's laptop lists bo after {told and round(told, 1)} s")
    told = wait("bo's laptop hears of ana", 30, lambda: "Ana" in bo.cli("contacts"))
    print(f"bo's laptop lists Ana after {told and round(told, 1)} s")

    who = ana.cli("contacts").split()[0]
    said = {}

    def ana_says():
        r = ana.run("say", who, "written while bo's laptop is off")
        said["out"] = (r.stdout + r.stderr).strip()
        return r.returncode == 0

    opened = wait("ana's laptop opens the space", 60, ana_says)
    print(f"ana's laptop can speak after {opened and round(opened, 1)} s: {said['out']}", flush=True)
    bo.stop()
    time.sleep(3)
    bo.roam("cafe", 3)
    bo.start()
    got = wait("bo reads it", 60, lambda: "while bo" in bo.cli("messages", "Ana"))
    print(f"bo's laptop, back on at a cafe, reads it after {got and round(got, 1)} s")
    print(bo.cli("messages", "Ana").strip())
    bo.cli("say", "Ana", "from the cafe")
    got = wait("ana reads it", 60, lambda: "from the cafe" in ana.cli("messages", who))
    print(f"ana's laptop reads the reply after {got and round(got, 1)} s")
    print("what ana's laptop says of bo:", ana.cli("contacts").strip())
    for d in (ana, bo, ana_host, bo_host):
        d.stop()


def talk(a, b, frames=250):
    """Each side sends numbered, timestamped frames every 20 ms, as a call's
    sound goes, and says what arrived and how late."""
    heard = {a.name: [], b.name: []}
    lines = {}
    for d in (a, b):
        s = socket.socket(socket.AF_UNIX)
        s.connect(d.env["CARDINAL_SOCKET"])
        s.sendall(b'{"cmd": "call-media"}\n')
        lines[d.name] = s

    def listen(name):
        f = lines[name].makefile()
        lines[name].settimeout(2)
        try:
            for line in f:
                v = json.loads(line)
                if "audio" in v:
                    seq, sent = struct.unpack(">Id", bytes.fromhex(v["audio"])[:12])
                    heard[name].append((seq, time.time() - sent))
        except (OSError, ValueError):
            pass

    readers = [threading.Thread(target=listen, args=(n,), daemon=True) for n in heard]
    for t in readers:
        t.start()
    time.sleep(0.3)
    for n in range(frames):
        for d in (a, b):
            frame = struct.pack(">Id", n, time.time()) + bytes(60)
            lines[d.name].sendall((json.dumps({"audio": frame.hex()}) + "\n").encode())
        time.sleep(0.02)
    time.sleep(1)
    for s in lines.values():
        s.close()
    for t in readers:
        t.join(3)
    out = {}
    for d, other in ((a, b), (b, a)):
        got = heard[other.name]
        late = sorted(x[1] * 1000 for x in got)
        p99 = late[min(len(late) - 1, int(len(late) * 0.99))] if late else None
        out[f"{d.name} to {other.name}"] = (len(got), frames,
                                            late and round(statistics.median(late), 1),
                                            p99 and round(p99, 1))
    return out


def cousin(theirs, label):
    """Daniel and his cousin as they are: Daniel's home behind a strict router
    (pfSense-style) with only the host forwarded, and the cousin's behind
    `theirs` with no host of his own. Daniel invites him from his laptop, as a
    window does, and the invitation names his host, the one device of his that
    anyone can reach. A message, a call each
    way with frames counted and timed, and Daniel's laptop going away and
    coming back."""
    net = Net()
    net.router("dan-home", "internet", "198.51.100.10", "198.51.100.1", "192.168.1", "hard",
               forward="192.168.1.2")
    if theirs == "cgnat":
        net.router("carrier", "internet", "198.51.104.10", "198.51.104.1", "100.64.0", "easy")
        net.router("cousin-home", "carrier", "100.64.1.10", "100.64.1.1", "192.168.2", "easy",
                   up_if="to-cousin")
        sh("ip netns exec carrier nft add rule ip filter through "
           'iifname "to-cousin" accept')
    else:
        net.router("cousin-home", "internet", "198.51.101.10", "198.51.101.1", "192.168.2",
                   theirs)
    nuc = Dev(net, "nuc", "dan-home", 2)
    laptop = Dev(net, "carbonite", "dan-home", 3)
    him = Dev(net, "cousin", "cousin-home", 3)
    nuc.start()
    nuc.cli("init", "--yes", "--name", "nuc")
    laptop.start()
    pair(nuc, laptop)
    nuc.cli("host", "--address", "198.51.100.10:7171")
    wait("paired", 30, lambda: laptop.online("nuc"))
    him.start()
    him.cli("init", "--yes", "--name", "cousin")
    sheet = nuc.cli("recovery", "sheet")
    key = next(l.split()[-1] for l in sheet.splitlines() if "Key:" in l)
    wait("the laptop knows of its host", 30, lambda: key in laptop.cli("recovery", "sheet"))
    code = laptop.cli("invite", "--name", "Daniel").strip()
    wait("the host has the invitation", 10, lambda: False)
    t0 = time.monotonic()
    him.cli("accept", code, "--name", "Daniel")
    print(f"{label}:", flush=True)
    found = wait("found", 120, lambda: laptop.contact().get("connected"))
    print(f"    his device reached Daniel's laptop {found and round(time.monotonic() - t0)} s "
          f"after accepting; relayed: {laptop.contact().get('relayed')}", flush=True)
    if not found:
        print("    log:", "\n    log: ".join(him.log().splitlines()[-12:]), flush=True)
        for d in (him, laptop, nuc):
            d.stop()
        sh("for n in $(ip netns list | cut -d' ' -f1); do ip netns del $n; done", check=False)
        return

    him.cli("say", "Daniel", "can you hear me")
    got = wait("message", 30, lambda: "can you hear me" in laptop.cli("messages", "cousin"))
    print(f"    his message reached the laptop in {got and round(got, 1)} s", flush=True)

    for caller, callee, who in ((laptop, him, "cousin"), (him, laptop, "Daniel")):
        rung = time.monotonic()
        r = caller.ask({"cmd": "call-start", "who": who})
        ringing = wait("ringing", 20, lambda: callee.call_state() == "ringing")
        if not ringing:
            print(f"    {caller.name} calls: {r}; it never rang", flush=True)
            continue
        callee.ask({"cmd": "call-answer"})
        live = wait("live", 10, lambda: caller.call_state() == "live")
        print(f"    {caller.name} calls: rang in {round(time.monotonic() - rung, 1)} s, "
              f"live: {live is not None}", flush=True)
        for way, (n, sent, median, p99) in talk(caller, callee).items():
            print(f"      {way}: {n} of {sent} frames, one-way median {median} ms, "
                  f"p99 {p99} ms", flush=True)
        caller.ask({"cmd": "call-end"})
        wait("ended", 10, lambda: callee.call_state() is None)

    laptop.stop()
    time.sleep(2)
    laptop.start()
    back = wait("back", 120, lambda: laptop.contact().get("connected"))
    print(f"    the laptop restarted, and he had it again in {back and round(back)} s", flush=True)
    for d in (him, laptop, nuc):
        d.stop()
    sh("for n in $(ip netns list | cut -d' ' -f1); do ip netns del $n; done", check=False)


PCP_ROUTER = r"""
import socket, struct, subprocess, sys
wan = socket.inet_aton(sys.argv[1])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", 5351))
held = {}
while True:
    b, addr = s.recvfrom(1100)
    if len(b) < 60 or b[0] != 2 or b[1] != 1:
        continue
    lifetime = struct.unpack(">I", b[4:8])[0]
    internal, wanted = struct.unpack(">HH", b[40:44])
    key = (addr[0], internal)
    if lifetime and key not in held:
        # a port outside another device holds is not given twice
        while wanted in held.values():
            wanted += 1
        held[key] = wanted
        subprocess.run(["nft", "add", "rule", "ip", "nat", "pre", "iifname", "wan", "udp",
                        "dport", str(wanted), "dnat", "to", f"{addr[0]}:{internal}"], check=True)
        print(f"pcp: {addr[0]}:{internal} mapped to {wanted} outside", flush=True)
    outside = held.get(key, wanted)
    r = bytes([2, 0x81, 0, 0]) + struct.pack(">I", min(lifetime, 3600)) + bytes(16)
    r += b[24:36] + bytes([17, 0, 0, 0]) + struct.pack(">HH", internal, outside)
    r += bytes(10) + b"\xff\xff" + wan
    s.sendto(r, addr)
"""


def mapped():
    """D72, end to end. Daniel's laptop at home behind a strict router that
    answers PCP, with no forward and no host; his cousin visits, they meet
    on the home network, and the cousin goes home behind a strict router of
    his own. All his device has of the laptop is the reach node of their
    relationship, which names the laptop at the port the router gave it.
    It reaches the laptop directly, no relay."""
    net = Net()
    net.router("dan-home", "internet", "198.51.100.10", "198.51.100.1", "192.168.1", "hard")
    net.router("cousin-home", "internet", "198.51.101.10", "198.51.101.1", "192.168.2", "hard")
    pcp_log = open(f"{WORK}/pcp.log", "w")
    pcp = subprocess.Popen(["ip", "netns", "exec", "dan-home", "python3", "-I", "-c", PCP_ROUTER,
                            "198.51.100.10"], stdout=pcp_log, stderr=pcp_log)
    laptop = Dev(net, "carbonite", "dan-home", 3)
    him = Dev(net, "cousin", "dan-home", 4)
    laptop.start()
    laptop.cli("init", "--yes", "--name", "Daniel")
    got = wait("a port", 30, lambda: laptop.status()["router"].get("external"))
    print(f"mapped:\n    the router gave the laptop {laptop.status()['router'].get('external')} "
          f"after {got and round(got, 1)} s", flush=True)
    named = wait("named", 30, lambda: laptop.status()["router"].get("named"))
    print(f"    it names itself at {laptop.status()['router'].get('named')}", flush=True)
    him.start()
    him.cli("init", "--yes", "--name", "cousin")
    code = laptop.cli("invite", "--address", f"{laptop.ip}:7171", "--name", "Daniel").strip()
    him.cli("accept", code, "--name", "Daniel")

    def reach_named():
        v = him.ask({"cmd": "contact-status", "who": "Daniel"})
        eps = [e["endpoint"] for r in v.get("their_reach") or [] for e in r["endpoints"]]
        return eps or None

    told = wait("told", 60, reach_named)
    print(f"    his device read the laptop's reach node after {told and round(told, 1)} s: "
          f"{reach_named()}", flush=True)
    him.stop()
    him.roam("cousin-home", 4)
    him.start()
    t0 = time.monotonic()
    him.run("say", "Daniel", "home again")

    def daniel():
        v = him.ask({"cmd": "contact-status", "who": "Daniel"})
        return next((d for d in v.get("devices") or [] if d.get("online")), None)

    found = wait("reached", 90, daniel)
    d = daniel() or {}
    print(f"    back home, his device reached the laptop after "
          f"{found and round(time.monotonic() - t0)} s: route {d.get('route')}, "
          f"at {d.get('addr')}, opened by {d.get('opened_by')}", flush=True)
    got = wait("message", 30, lambda: "home again" in laptop.cli("messages", "cousin"))
    print(f"    the laptop has his message: {got is not None}", flush=True)
    if not found:
        print("    log:", "\n    log: ".join(him.log().splitlines()[-15:]), flush=True)
    for x in (him, laptop):
        x.stop()
    pcp.kill()
    pcp_log.close()
    print("    router:", open(f"{WORK}/pcp.log").read().strip().replace("\n", "\n    router: "),
          flush=True)
    sh("for n in $(ip netns list | cut -d' ' -f1); do ip netns del $n; done", check=False)


os.makedirs(SOCKETS, exist_ok=True)
os.makedirs(WORK, exist_ok=True)
if "trace" in WHICH:
    punch("easy", "easy", "ordinary NAT on both sides, traced", trace=True)
if "cgnat" in WHICH:
    punch("easy", "cgnat", "ordinary NAT at the cafe, carrier-grade NAT at the airport")
if "punch" in WHICH:
    punch("easy", "easy", "ordinary NAT on both sides")
    punch("hard", "easy", "strict NAT at the cafe (pfSense-style), ordinary at the airport")
    punch("hard", "hard", "strict NAT on both sides")
    punch("easy", "cgnat", "ordinary NAT at the cafe, carrier-grade NAT at the airport")
if "people" in WHICH:
    people()
if "mapped" in WHICH:
    mapped()
if "cousin" in WHICH:
    cousin("easy", "his home behind an ordinary router")
    cousin("cgnat", "his home behind carrier-grade NAT")
