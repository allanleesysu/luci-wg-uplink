# WG Uplink

A LuCI page and local controller for preferred/fallback WireGuard uplinks on OpenWrt.

**Network → WG Uplink**

The page lists every saved WireGuard interface and any runtime-only WG devices. Only enabled peers with a **configured endpoint** can be managed. A learned endpoint on an inbound-only peer does not make it an outbound peer.

The counterpart is assumed to have one uplink, or to already implement sticky return-path routing. This application controls the local router only. The optional, independently installed receiver service covers a counterpart with multiple uplinks.

## Features

- Per-peer preferred and fallback logical uplink, with IPv4/IPv6 preference.
- Optional other-family fallback on the same provider, followed by active restoration of the preferred family.
- Per-peer pings per target per check: **5** by default, independently configurable from1–20 under Failover and Recovery.
- Separate configurable failover and recovery checks: ping loss thresholds/targets, generic TCP acceptance or iperf3 response, and DNS resolution.
- Observed failure and recovery windows: **300 seconds** by default.
- Corroborated local Internet/uplink failure fast track: **10 seconds** by default.
- Active recovery even while the fallback works.
- Shared remote-failure guard: retain the current path when all candidates fail.
- Sticky routing, ingress/egress device guards, and endpoint-family enforcement.
- Live candidate results, endpoint, handshake time, observation progress and errors.
- Optional inner-tunnel verification and rollback of a failed trial.
- Bounded RAM status/history; no periodic flash writes.

New policies default to ping only: fail at 100% loss and recover below 100% loss. TCP and DNS can be enabled independently. Generic TCP defaults to port443; iperf3 commonly uses5201. Migrated settings are preserved.

## Usage

1. Open Network → WG Uplink, then Configure on a peer with a saved endpoint.
2. Enable management and select two different uplinks.
3. Choose each uplink's preferred IP family.
4. Set failover/recovery checks and windows.
5. Save & Apply.

A reachable preferred family is not replaced by a lower-priority family merely because that family meets a stricter recovery policy sooner. Loss is evaluated against the configured threshold.

If the peer uses separate A/AAAA hostnames, enter IPv4/IPv6 aliases under Advanced. Network endpoint definitions and private keys are not rewritten.

Static uplinks without a gateway need a gateway override. Devices, native addresses and gateways are derived from netifd, including DHCPv6 siblings and MBIM child interfaces. No fixed USB/device indices are required.

Select the parent uplink (for example wan3). The controller resolves netifd's wan3_4/wan3_6 children and configured device=@parent aliases separately for each IP family, even when the child has a different L3 device. PPPoE's dynamically created _6 is handled the same way. Gateway-free PPP defaults are supported. The dropdown names detected children, and live checks show the resolved logical interface plus device. Down children are not treated as usable through stale kernel addresses.

IPv6 probes require a usable native global source address on the resolved path; a delegated prefix alone is not a WAN source address.

Candidate checks are outside WireGuard and source-pinned. Optional verification addresses are checked inside WG after selection; at least one must reply.

### Timing

Probe interval defaults to10seconds and is configurable from5–60seconds. Timers use monotonic elapsed time. Monitoring gaps restart observation; extra hotplug/check requests cannot shorten it. Actual switch time includes probe/scheduler latency.

### Ping sample size

In a peer's Failover and Recovery tabs, set **Pings per check** independently. Both default to5, including existing configurations without an explicit count. Each setting applies per target and candidate path. Identical target/count samples are shared between failure and recovery; different counts use independent samples.

One target with5 probes gives20-percentage-point steps. Multiple targets combine actual sent/received counts for that check. This is not a rolling average over the observation window. Targets run in parallel; larger samples may lengthen a monitoring cycle, so the probe interval is a minimum scheduling interval.

### TCP and DNS

Generic TCP requires a connection to be accepted. The iperf3 check sends a37-byte cookie, reads one protocol-state byte and closes before parameters/streams. It never runs a bandwidth test. A busy response proves service reachability.

DNS checks bind the candidate source address, query A/AAAA according to family, and try TCP if UDP does not answer. Defaults are Cloudflare and Google in that family; custom servers are supported.

### Sticky paths

Destination/address-family/UDP-port rules and the WG interface mark select each peer's uplink. Different peers on one WG interface can use different uplinks.

Provider tables have unreachable defaults to prevent fall-through to another WAN. Input/output guards constrain known endpoint traffic to the selected device/family. Endpoint updates and route-cache invalidation prevent an old cached underlay from surviving a switch.

Existing nonzero WG marks are retained. A newly assigned mark is restored when the last policy on the interface is disabled. Private/preshared keys are never returned by RPC.

Two devices sharing the same source IP are rejected rather than reporting incorrectly attributed health results.

## Receiver tab and independent installation

The **Receiver** tab shows every running WG interface, its listener and each peer's status: **Actively pinned**, **Enabled; waiting for inbound traffic**, **Excluded: locally initiated**, or **Disabled**. Active pins include the learned remote endpoint, return uplink/device and IP family.

The receiver learns incoming WG UDP flows in the kernel and routes replies through the same uplink. Its separate configuration, daemon and package work without this LuCI app. The selector can remain entirely disabled while receiver learning runs.

- Initiating router: install this app; enable only the intended outbound peer policies.
- Receiving router: install only [receiver/](receiver/README.md), with no LuCI dependency.
- Router doing both: install both and manage the independent receiver through the Receiver tab.

## Installation

### OpenWrt package build

Place this directory in a LuCI feed's applications/luci-app-wg-uplink directory, then build with the normal SDK/buildroot. The Makefile declares dependencies and the UCI conffile.

This repository contains source; no SDK-built APK/IPK is claimed.

### Manual source installation

Requires root, WG tools, ip-full, nftables, ucode/UCI, rpcd ucode support and Python3.

    python3 install.py --install --activate

To include the independently running receiver addon:

    python3 install.py --install --with-receiver --activate

Existing /etc/config/wg_uplink is preserved. The installer adds installed files to sysupgrade preservation. With --activate, it restarts rpcd and enables/starts the service.

The launcher also supports Kwrt's existing private Python runtime at /opt/wgclients-python. It does not replace system libraries or install that runtime.

No outbound policy or receiver learning is enabled by the generic installer. Configure actual interfaces in LuCI and refresh LuCI after installation.

## Operations

    /etc/init.d/wg-uplink status
    /etc/init.d/wg-uplink restart
    /usr/sbin/wg-uplink status
    /usr/sbin/wg-uplink kick

- Configuration: /etc/config/wg_uplink
- RAM state: /var/run/wg-uplink/
- History: /var/run/wg-uplink/history/
- Service: wg-uplink

An old controller's entry point can delegate to "wg-uplink kick". Retire its independent cron/route writer before managing the same peer here.

Owned resources for peer slots1–32: selection priorities301–332, source priorities504–631, and tables starting48008. Initial collisions are rejected. The owned nftables table is "inet wg_uplink". Other network/firewall UCI, management policies and per-client IPv6 controls are not rewritten.

Disabling a policy removes its owned rules/tables and restores its original endpoint. The original interface mark is restored when no managed peers remain. Disable policies and stop the service before package removal.

After an OS/ABI upgrade, reinstall matching runtime dependencies if needed. RAM history/timers reset on reboot.

## Tests

Backend tests without real network changes:

    python3 tests/test_backend.py root/usr/libexec/wg-uplink.py

Receiver tests:

    python3 tests/test_receiver.py
    python3 tests/test_family.py

Render and form serialization fixture (Node.js on a development machine):

    node tests/test_render.js htdocs/luci-static/resources/view/network/wg_uplink.js status.json

Use a sanitized status response for status.json; it is not checked into Git.

Optional root-only installed-instance checks: tests/test_live_rpc.py and tests/test_http_ui.py.
The RPC test expects one enabled IPv6-preferred peer, saves the same policy, and makes bounded DNS/TCP probes without bandwidth tests. HTTP checks use short-lived test sessions, not a user's password.

JavaScript syntax/render fixtures and authenticated HTTP route/RPC tests were used during deployment. Browser visual acceptance is separate.

## Upstream components

Uses LuCI/rpcd/ucode, netifd, Linux policy routing, nftables and WireGuard tools; no new tunnel protocol.

- [OpenWrt PPP IPv6 dynamic-child implementation](https://git.openwrt.org/openwrt/openwrt/tree/?path=package%2Fnetwork%2Fservices%2Fppp%2Ffiles%2Flib%2Fnetifd%2Fppp6-up)
- [OpenWrt MBIM setup](https://openwrt.org/docs/guide-user/network/wan/wwan/ltedongle)
- [LuCI](https://github.com/openwrt/luci)
- [WireGuard tools](https://git.zx2c4.com/wireguard-tools/)
- [iperf3 protocol](https://github.com/esnet/iperf/blob/master/src/iperf_api.h)

See [design and ownership](docs/DESIGN.md) for the routing model, policy semantics and migration notes.

MIT licensed; see LICENSE.
