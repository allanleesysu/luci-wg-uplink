# Design and operations

## Separate roles

The selector manages peers with an endpoint saved in network UCI. A runtime endpoint learned from incoming traffic does not grant eligibility. It never exports private or preshared keys.

The receiver is an independent package/service with its own UCI file and runtime state. It learns only UDP packets delivered to local WG listen ports. A locally initiated peer's current endpoint is excluded from receiver learning. The optional LuCI tab calls its status/configuration CLI.

Both modules can run on the same router. A receiving-only router needs only receiver/. A selector-only router does not need the receiver package.

## Selection state machine

Candidates are ordered preferred-family, optional other preferred-provider family, fallback-family, optional other fallback-provider family. Both families are probed even if a secondary family is not selectable; this supports distinguishing provider failure from a common remote outage.

Each candidate runs independent source-bound checks. Failover and recovery have independent targets, thresholds and all/any combinations. Defaults require complete ping loss for failure and at least one reply for recovery. A process exit code alone never represents ping loss.

When all candidates fail the configured failure policy, selection is retained. A hub outage therefore does not trigger an arbitrary provider switch. A failed selected path switches only after a qualifying alternative survives the observation window. General Internet reachability corroborates the fast local-uplink-failure branch.

A working fallback is continuously evaluated for active return to the preferred path. The highest-priority reachable family blocks substitution by another family while its stricter recovery policy is not yet satisfied. Timers use monotonic elapsed time; candidate changes and monitoring gaps reset them. Defaults: observed failure 300s, recovery 300s, fast local failure 10s.

A switch installs path guards and policy routing, invalidates the route cache, changes the runtime endpoint/mark, then verifies route selection and optional inner-tunnel reachability. Failed verification restores the prior path.

## Selector routing ownership

Each WG socket uses its existing fwmark when available. Otherwise the controller assigns a mark and remembers the old value. Per-peer destination, family and UDP destination-port rules permit separate peers on a WG interface to select different uplinks.

- RPDB endpoint rules: priorities301–332.
- RPDB source probe rules: priorities504–631.
- Tables:48008–48259, four candidate tables per peer with slot spacing8.
- nftables table: inet wg_uplink.

Tables contain provider-specific routes and an unreachable default with higher metric, preventing leakage through the ordinary default. Endpoint input/output guards prevent roaming onto another provider or family. Source rules pin health probes.

Only resources with ownership recorded in RAM are cleaned up. Initial collisions with other routing rules/tables are errors. Disabling a policy removes its routes/guards and restores the captured original endpoint. On last-policy disable, the original interface fwmark is restored.

Configuration writes are restricted to the app's own UCI file. Network/firewall UCI and unrelated routing tables are left alone.

## Receiver routing ownership

- Reserved ct/meta mark bits:0x3f000000; all other bits are retained.
- RPDB priorities:201–232.
- Return tables:49002–49065.
- nftables table: inet wg_uplink_receiver.

An INPUT hook marks inbound local WG flows according to ingress uplink. A route OUTPUT hook restores those reserved bits, causing Linux to reroute the local reply. Per-flow conntrack state avoids remote-IP-only rules that break when peers share a NAT address.

Existing UDP flows may have been initiated in either conntrack direction. Configured outbound endpoint exclusions run before learning/restoration. Removed uplink slots retain unreachable routing while enabled and are not reused within the same boot. Conntrack expiration removes old flow pins naturally.

Discovery refreshes the available upstream interfaces, addresses/gateways and WG listeners; learning happens in the kernel per packet between refreshes. No tcpdump watcher process is required.

The receiver does not open ports, accept firewall traffic, alter NAT or configure WG peers. A pre-existing firewall must allow the intended listener. Mark bits and routing ranges must be free of conflicting customization.

Status correlates marked conntrack flows with authenticated WG runtime endpoints. An enabled peer without a current marked flow is shown as waiting, rather than claiming a working pin.

## Deployment and migration

1. Back up relevant UCI, custom services/hotplug scripts, cron and RPDB/tables.
2. Install without overwriting existing app configuration.
3. Save peer/uplink policy. Observe the actual endpoint, route proof and probes.
4. Retire any older controller managing that same peer.
5. If adding the receiver, verify syntax and live pins before retiring the older return-path watcher.
6. Validate management and data tunnels after the old rules are removed.

The manual installers preserve installed paths in sysupgrade.conf. SDK packaging also declares conffiles. Runtime history/timers are in RAM and reset at boot. The Python launcher supports a normal system Python3 or Kwrt's pre-existing private runtime; no private runtime is bundled.

For removal, disable the relevant policies/receiver and let cleanup finish before stopping/disabling services. The two services can be removed independently.

## Validation scope

Unit fixtures cover policy validation, timer boundaries, active recovery, shared failure, partial-loss behavior, routing guards, failed-cutover rollback and resource ownership. Receiver fixtures check port/family rules, outbound exclusion, mark preservation, existing-flow migration and cleanup ownership.

Installed-instance checks exercise authenticated LuCI HTTP/RPC, rejected unauthenticated/read-only writes, same-policy Save & Apply, candidate source-bound DNS/TCP and live WG connectivity. UI fixtures exercise rendering and both configuration forms.

The optional namespace traffic test requires veth support; it is not a pass when the kernel lacks that module. No SDK-built package or browser visual inspection is implied by source/HTTP checks.
