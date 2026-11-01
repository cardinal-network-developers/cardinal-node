#!/usr/bin/env python3
"""An internet in a box: real daemons behind real kernel NAT, with no root.

Run through scripts/lab.sh, inside fresh user, network, mount and pid
namespaces. Nothing here can reach the real network or see a process outside
the lab, which is how to test what takes more devices and networks than
there are to hand. Every link has a delay (LAB_DELAY_MS), because with none
each pair of packets crosses at once and no hole can be punched.

    internet ── ana-home  (router, UDP 7171 forwarded to ana-host)
             ├─ bo-home   (router, UDP 7171 forwarded to bo-host)
             ├─ cafe      (router, no forward)
             ├─ airport   (router, no forward)
             └─ carrier ── tower (a second NAT: carrier-grade NAT)
"""

import json
import os
import shutil
import subprocess
import sys
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
