# WG Sticky Receiver

Independent receiver-side service for OpenWrt. **No LuCI, no WG Uplink selector, and no outbound uplink policy is required.**

It automatically discovers local WG listen ports and upstream netifd interfaces with native addresses/gateways. A configured local-outbound peer's current endpoint is excluded. Other incoming WG UDP flows are marked by ingress uplink; local replies restore that mark and use the same uplink.

Learning is in nftables/conntrack, not one tcpdump process per listener. It also handles existing flows regardless of which direction created the conntrack entry.

## Install on the receiving router

    python3 install.py --install --activate
    wg-sticky-receiver enable

Defaults are disabled until explicitly enabled. A normal WAN setup requires no per-peer configuration.

Optional restrictions/overrides:

    wg-sticky-receiver configure '{"enabled":"1","uplinks":["wan1","wan2"],"gateways":[],"interval":10}'

Static upstreams without default gateways need entries such as "wan2=192.0.2.1". Do not guess downstream LANs as uplinks; autodetection deliberately requires an upstream gateway.

Dependencies: Python3, WireGuard tools, ip-full, firewall4/nftables, ucode/UCI, ubus, and conntrack (or the kernel conntrack proc file). There is no LuCI/rpcd dependency.

The Makefile can build a separate wg-sticky-receiver package. The manual installer preserves configuration and adds installed files to sysupgrade preservation.

## Optional LuCI management

If the full WG Uplink app is also installed, its **Receiver** tab configures this independent service and shows live per-interface/per-peer pin status. Outbound policies can all remain disabled.

The receiver still runs without the app. It does not use or require that app's state files.

## Status and controls

    wg-sticky-receiver status
    wg-sticky-receiver plan
    wg-sticky-receiver disable
    /etc/init.d/wg-sticky-receiver status

- Configuration: /etc/config/wg_sticky
- RAM state: /var/run/wg-sticky-receiver/
- Owned nft table: inet wg_uplink_receiver
- Reserved mark bits: 0x3f000000
- Routing priorities: 201–232
- Routing tables: starting49002

Other mark bits are preserved. A WG socket already using the reserved bits is rejected. Do not allocate these bits/priorities/tables to another routing system.

Each ingress uplink has IPv4/IPv6 return tables with unreachable defaults. Removed uplink slots retain fail-closed handling while enabled and are not reused in the same boot. Conntrack expiry removes old per-flow learning naturally.

The status associates marked UDP flows with WireGuard's authenticated learned endpoints. It reports:
- actively pinned, including uplink/device/family;
- enabled but waiting for inbound traffic;
- excluded because a local endpoint is configured.

The module does not accept firewall traffic, open WAN ports, change NAT, or configure remote peers. Existing firewall/port-forwarding rules must already allow the intended WG listener.

## Migration and removal

Retire any older sticky route watcher only after verifying the new live pins and return paths. Do not leave independent writers managing the same receiver.

Before removing this service, disable it and allow cleanup to finish, then stop/disable its init service. It owns only its own routes/rules/nft table; ordinary defaults and WG peer configuration are unchanged.

## Tests

From the repository root:

    python3 tests/test_receiver.py

The optional namespace test requires root, network namespaces and kmod-veth:

    python3 tests/test_receiver_netns.py

Nft syntax and actual live WG peer pins were checked during deployment. The namespace test cannot run on kernels without veth support.
