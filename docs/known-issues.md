# Known Issues

This file keeps the items that have no ticket of their own: minor faults,
limits and open questions. When an item gets a Polarion ticket, the ticket
becomes its record and the entry leaves this file.

## The bridge refuses every outside MLD querier while it cannot query itself

**Status:** Known, not addressed. Found on 2026-10-01 and 2026-10-02 during
the work on SDG-9671, on an SDG-8612 and an SDG-8733v with image 26.9.0.101,
kernels 6.18.52 and 6.18.54. The SDG-9671 description states that mainline
has the same code.

### Symptom

A bridge multicast context with `mcast_querier 1`, on a bridge without an
IPv6 address, records no outside MLD querier. `mcast_querier_ipv6_addr`
stays `::`, and the bridge floods IPv6 multicast to every port of the VLAN.

After the bridge accepts a querier once, for example after
`multicast_querier` was 0 for a while, it accepts that querier again until
the bridge is created again. So a runtime test hides the fault until a
reboot.

### Root cause

From `net/bridge/br_multicast.c`:

- `br_ip6_multicast_alloc_query()` finds no IPv6 source address and makes
  no query. `br_multicast_send_query()` starts the own query timer all the
  same.
- `br_multicast_select_querier()` accepts an IPv6 querier only when its
  address is lower than or equal to the stored address, which is `::`, or
  when neither the own nor the other query timer runs. So it refuses every
  querier.
- `__br_multicast_querier_exists()` ignores the own querier while the bridge
  has no IPv6 address, so for IPv6 no querier exists.
- A query that the bridge device sends itself, such as the query of
  `mcproxy` on a VLAN device of `br0`, is stored with port 0.
  `br_multicast_send_query()` clears the stored address only when the port
  is not 0. So the address stays, and an equal address passes.

### Why it is left alone

`set_fast_leave.sh` (bsp-scripts) turns on per-VLAN snooping on `br0`
(SDG-9671). It sets `mcast_querier 0` on the VLANs where `mcproxy` queries,
so the own query timer does not run there. In the other VLANs nobody sends
an MLD query, so the fault only keeps the IPv6 flood there. The flood keeps
neighbour discovery working (SDG-9685).

### Direction

Let `br_multicast_select_querier()` accept an IPv6 querier while the bridge
cannot send its own query, or let `br_multicast_send_query()` leave the own
timer stopped when it sent no query. Mainline has the same code, so the
change can go to netdev. Do not ship it on a `br0` without per-VLAN
snooping: a querier of one VLAN would then turn on IPv6 snooping in every
VLAN (SDG-9685).
