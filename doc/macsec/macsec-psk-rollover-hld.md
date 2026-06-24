<!-- omit in toc -->
# MACsec PSK/CAK Rollover — High Level Design Document

***Revision***

|  Rev  |    Date    |     Author     | Change Description |
| :---: | :--------: | :------------: | ------------------ |
|  0.1  | 2025-06-09 | Liam Kearney   | Initial version    |
|  1.0  | 2026-06-23 | Liam Kearney   | Warm dual-SAK design for hitless, non-simultaneous PSK/CAK rollover |

<!-- omit in toc -->
## Table of Contents

- [About this Manual](#about-this-manual)
- [Scope of this Document](#scope-of-this-document)
- [Abbreviation](#abbreviation)
- [Background: Key Hierarchy and Two Kinds of Rollover](#background-key-hierarchy-and-two-kinds-of-rollover)
  - [Why a warm fallback is required: non-simultaneous rollover](#why-a-warm-fallback-is-required-non-simultaneous-rollover)
- [1 Requirements Overview](#1-requirements-overview)
  - [1.1 Functional Requirements](#11-functional-requirements)
  - [1.2 Hardware Requirements](#12-hardware-requirements)
  - [1.3 Non-Functional Requirements](#13-non-functional-requirements)
- [2 Design Overview](#2-design-overview)
  - [2.1 Problem Statement](#21-problem-statement)
  - [2.2 Approach — Warm Dual-SAK Standby](#22-approach--warm-dual-sak-standby)
  - [2.3 IEEE 802.1X-2020 Justification](#23-ieee-8021x-2020-justification)
  - [2.4 Alternative Considered — Per-CAK Secure Channels](#24-alternative-considered--per-cak-secure-channels)
- [3 Detailed Design](#3-detailed-design)
  - [3.1 KaY Multi-Participant Model](#31-kay-multi-participant-model)
  - [3.2 Shared Secure Channel Architecture](#32-shared-secure-channel-architecture)
  - [3.3 Transmit-Owner Selection](#33-transmit-owner-selection)
  - [3.4 AN Allocation (§9.9)](#34-an-allocation-99)
  - [3.5 Transmit Ownership and Draining](#35-transmit-ownership-and-draining)
    - [3.5.1 How the peer keeps receiving across a transmit switch](#351-how-the-peer-keeps-receiving-across-a-transmit-switch)
    - [3.5.2 Session teardown and peer failover](#352-session-teardown-and-peer-failover)
  - [3.6 MKA Life Time Enforcement (§9.5, §9.3.2)](#36-mka-life-time-enforcement-95-932)
  - [3.7 SA Install Model and the §9.10 Deviation](#37-sa-install-model-and-the-910-deviation)
  - [3.8 Controlled Port State Machine Interaction](#38-controlled-port-state-machine-interaction)
- [4 Config DB Schema](#4-config-db-schema)
- [5 wpa\_supplicant Changes](#5-wpa_supplicant-changes)
  - [5.1 Configuration File](#51-configuration-file)
  - [5.2 Runtime Key Management (wpa\_cli)](#52-runtime-key-management-wpa_cli)
  - [5.3 Status Output](#53-status-output)
- [6 Operational Flows](#6-operational-flows)
  - [6.1 Initial Setup with Backup Key](#61-initial-setup-with-backup-key)
  - [6.2 Hitless Primary Key Rollover (non-simultaneous)](#62-hitless-primary-key-rollover-non-simultaneous)
  - [6.3 Hitless Fallback Key Update](#63-hitless-fallback-key-update)
  - [6.4 Emergency Key Revocation](#64-emergency-key-revocation)
- [7 IEEE Spec Conformance](#7-ieee-spec-conformance)
  - [7.1 Spec Deviations](#71-spec-deviations)
- [8 Implementation Outline](#8-implementation-outline)
  - [8.1 Components Touched](#81-components-touched)
  - [8.2 Warm Dual-SAK Behaviours](#82-warm-dual-sak-behaviours)
- [9 Testing](#9-testing)
  - [9.1 Unit Tests](#91-unit-tests)
  - [9.2 VS (Virtual Switch) Tests](#92-vs-virtual-switch-tests)
- [10 Limitations and Future Work](#10-limitations-and-future-work)

## About this Manual

This document describes the design of PSK/CAK rollover (hitless key rotation) for MACsec in SONiC's wpa\_supplicant fork. It implements the existing MACsec HLD Phase III requirement: "Primary and Fallback secure Connectivity Association Key can be supported simultaneously."

## Scope of this Document

This HLD covers changes within the **wpa\_supplicant** codebase only — specifically the KaY (MKA), control interface, and CLI layers. It does **not** modify MACsec Mgr, MACsec Orch, SAI, or the kernel MACsec driver; the changes are transparent to those components because they operate at the MKA participant level, which is entirely internal to wpa\_supplicant.

The existing Config DB schema already contains `fallback_cak` and `fallback_ckn` fields in `MACSEC_PROFILE` (see MACsec HLD §3.1.1). This design provides the wpa\_supplicant-side support for those fields.

## Abbreviation

| Abbreviation | Description                              |
| ------------ | ---------------------------------------- |
| AN           | Association Number (0–3)                 |
| CA           | Connectivity Association                 |
| CAK          | Connectivity Association Key             |
| CKN          | CAK Name                                 |
| CP           | Controlled Port state machine            |
| KaY          | MACsec Key Agreement Entity              |
| MKA          | MACsec Key Agreement Protocol            |
| MKPDU        | MKA Protocol Data Unit                   |
| PSK          | Pre-Shared Key                           |
| SA           | Secure Association                       |
| SAK          | Secure Association Key                   |
| SAK rekey    | Replacing the SAK while keeping the same CAK — the normal, hitless MACsec data-plane rekey (a.k.a. same-CAK rekey) |
| CAK rollover | Replacing the CAK itself (new KEK/ICK, new participant) — what this design makes hitless, across CAKs |
| SC           | Secure Channel                           |
| SCI          | Secure Channel Identifier                |
| SecY         | MACsec Security Entity                   |
| XPN          | Extended Packet Numbering                |

## Background: Key Hierarchy and Two Kinds of Rollover

MACsec uses a two-level key hierarchy, and it is important to keep the two levels distinct because this design operates on both.

- **CAK (Connectivity Association Key)** — the long-lived pre-shared key (the `primary_cak` / `fallback_cak` of a `MACSEC_PROFILE`). It identifies CA membership and is used to derive the KEK and ICK that protect the MKA control protocol. In wpa\_supplicant each CAK/CKN is represented by one MKA **participant**.
- **SAK (Secure Association Key)** — the short-lived key that actually protects data-plane frames. The elected Key Server generates a fresh SAK and distributes it (wrapped under the KEK) to the other members. SAKs are installed in hardware as Secure Associations (SAs), identified on the wire by `(SCI, AN)`.

One CAK produces many SAKs over its lifetime. This gives two distinct "rollover" events:

| | What changes | How often | Hitless today? |
| --- | --- | --- | --- |
| **SAK rekey** (same-CAK) | a new **SAK** under the **same CAK** | frequently — on packet-number exhaustion, membership change, or `rekey_period` | **Yes** — built into MKA: the Key Server distributes the next SAK at a new AN, both ends install it alongside the current one, transmit switches AN, the old SAK retires |
| **CAK rollover** (this design) | the **CAK itself** (new KEK/ICK, a different CA-member identity, a new participant) | rarely — operator-driven key rotation | **No** in stock wpa\_supplicant — the new CAK's session must be established before it can carry traffic, which leaves a gap |

The central idea of this design is that **a CAK rollover can be made to behave like a SAK rekey**. The hardware does not care which CAK wrapped a given SAK — it matches frames by `(SCI, AN)`. So if the new CAK's SAK is installed at a second AN alongside the current one (exactly as a same-CAK SAK rekey does) and the transmit AN is then switched, the CAK boundary becomes invisible to the data plane and the rollover is hitless. The warm dual-SAK model (§2.2) and the §9.10 receive-side deviation (§3.7, §7.1) exist precisely to extend the SAK-rekey overlap that MKA already performs, across the CAK boundary.

### Why a warm fallback is required: non-simultaneous rollover

A CAK rollover is an operator action applied to each device independently, so the two ends of a link **never** change their primary CAK at exactly the same moment. There is always a window in which one end has rolled to the new primary CAK and the other has not — during which the two ends no longer share the *primary* CAK at all.

The fallback CAK bridges that window. As long as both ends still share an established fallback, a device that has rolled its primary can simply move its transmit onto the **fallback** SAK, which the peer can already receive, and continue without loss until the new primary is established on both ends. The rollover is thus a controlled detour through the fallback:

```
new primary on A only  →  A transmits on the (shared) fallback SAK
                          B still transmits on the old primary SAK
new primary on B too   →  both ends share the new primary  →  transmit returns to it
```

For this to be lossless, the fallback's receive SA must already be installed in hardware on **both** ends *before* either end starts the rollover — it cannot be brought up on demand at the moment of the switch (that would need a peer round trip and reintroduce a gap). This is the primary driver for keeping the fallback session **warm**: a live fallback SAK with an installed receive SA at all times, not merely an MKA session in standby. The warm dual-SAK model (§2.2) and the receive-side §9.10 deviation (§3.7) exist to satisfy exactly this requirement.

## 1 Requirements Overview

### 1.1 Functional Requirements

1. **Dual CAK/CKN support**: Two pre-shared keys (primary + fallback) can be configured per interface, either at startup or at runtime.
2. **Warm dual-SAK steady state**: Both the primary and fallback participants continuously hold a live SAK with **receive** SAs installed in hardware on both ends. Only the primary (the transmit owner) installs and enables a transmit SA. The fallback is always *receivable* but transmitted on only when it becomes the transmit owner.
3. **Hitless primary CAK rollover**: The primary CAK can be replaced on a live link with no traffic loss, even though the two ends are updated **non-simultaneously**. During the window where the two ends do not yet share the new primary, traffic rides the fallback SAK (which both ends already have installed), then returns to the new primary once both ends share it.
4. **Independent key lifecycle**: Each key (primary, fallback) can be added, replaced, or removed independently via `wpa_cli` at runtime.
5. **Graceful drain, not teardown**: When a CAK is rotated away, its participant is *drained* (transmit moves off it; its receive SAs are retained for MKA Life Time so the peer that has not yet switched keeps working) before it is deleted.

### 1.2 Hardware Requirements

1. **`max_sa_per_sc >= 4`**: The ASIC/PHY must support all 4 Association Numbers (ANs 0–3) per Secure Channel. If the hardware reports `max_sa_per_sc < 4`, wpa\_supplicant rejects the second participant and hitless rollover is unavailable on that platform. Most modern MACsec ASICs support 4 ANs; the 2-AN limit is mainly found on older or basic MACsec-capable NICs.

   The requirement of 4 follows from giving each CAK slot a **2-AN budget**: 1 AN for its current SAK plus 1 AN of headroom so it can perform a same-CAK SAK rekey (install the next SAK alongside the current one, then switch). With a primary and a fallback slot both kept warm, that is `2 + 2 = 4` ANs. At rest only 2 ANs are actually occupied (the two live SAKs); the other 2 are rekey headroom.

   A primary CAK rollover stays within this same 4-AN budget by temporarily repurposing the primary slot's 2 ANs for the transition:

   | Phase | Primary slot | Fallback slot | ANs in use |
   | ----- | ------------ | ------------- | ---------- |
   | Steady state | old primary SAK + rekey reserve (**2**) | fallback SAK + rekey reserve (**2**) | 2 live (+2 reserved) |
   | Rollover in progress | old primary **draining** (1 AN) + new primary **establishing** (1 AN) — the slot's 2 ANs are now used for the swap, not for a rekey reserve | fallback SAK carries traffic + reserve (**2**) | up to 4 |
   | After rollover | new primary SAK + rekey reserve (**2**) | fallback SAK + rekey reserve (**2**) | 2 live (+2 reserved) |

   In other words the budget goes `2+2` (primary + fallback, each with rekey reserve) → effectively `2` stable (just the fallback and its reserve) while the primary slot's 2 ANs drain the old primary and stand up the new one → back to `2+2` (new primary + fallback). Because the rollover reuses the primary slot's own 2-AN budget rather than demanding extra, 4 ANs is both necessary and sufficient; fewer than 4 cannot keep the fallback warm while a primary rollover (or a same-CAK rekey) is in flight.

### 1.3 Non-Functional Requirements

1. **Receive-side-only deviation**: The departure from strict §9.10 (see §3.7 and the Spec Deviations section) is confined to the **receive** path. Transmit remains single-principal, so the design cannot create the partial-connectivity that §9.10 guards against.
2. **Backward compatibility**: A single-key configuration (no `mka_cak2`/`mka_ckn2`) behaves identically to the unmodified codebase — one participant, one SAK, no warm standby.
3. **Driver-transparent**: MACsec Orch, SAI, and the kernel driver are unaware of the change — they see normal SA create/enable/delete operations; the only difference is that two receive SAs (from two CAKs) coexist on each RxSC.

## 2 Design Overview

### 2.1 Problem Statement

MACsec with PSK requires both endpoints to share the same CAK/CKN. Rotating this key today requires:

1. Disable MACsec on both ends
2. Configure the new key
3. Re-enable MACsec

This causes a traffic outage proportional to the MKA negotiation time (typically 3–6 seconds). In production networks, this is unacceptable for links carrying critical traffic.

### 2.2 Approach — Warm Dual-SAK Standby

The design runs **two MKA participants** within a single KaY — one per CAK/CKN pair. Both participants exchange MKPDUs independently, **both distribute and hold a live SAK**, and **both install receive SAs** in hardware. Only one participant — the **principal / transmit owner** — installs and enables a transmit SA; the other is a *warm* standby that can be received from but is not transmitted on.

Two facts make this work:

- **Receive SCs are shared.** Both participants face the same peer SCI, so their SAKs are installed as receive SAs on the same RxSC at different ANs. The driver matches incoming frames by `(SCI, AN)`, so a frame protected by either SAK is decryptable at any time.
- **Transmit is a per-AN choice.** A TxSC transmits on exactly one SA (the encoding SA) at a time. Switching the transmit owner is just enabling the new participant's TxSA and disabling the old — instant and local, requiring no peer round trip *because the peer already has the receive SA installed*.

```
KaY (one per interface)
├── Participant A (primary CAK)    ← transmit owner
│   ├── Sends MKPDUs with CKN_A, distributes SAK_A
│   ├── TxSC → TxSA[AN=0, SAK_A]              enableTransmit=true
│   └── RxSC[peer] → RxSA[AN=0, SAK_A]        enableReceive=true   ← shared RxSC
│
├── Participant B (fallback CAK)   ← warm standby
│   ├── Sends MKPDUs with CKN_B, distributes SAK_B
│   ├── No enabled TxSA (not transmitting)
│   └── RxSC[peer] → RxSA[AN=2, SAK_B]        enableReceive=true   ← same shared RxSC
│
└── SecY driver sees: one TxSC (one enabled TxSA), one RxSC, two enabled RxSAs at different ANs
```

Because the fallback's receive SA is **always** installed on both ends, a non-simultaneous primary CAK rollover is hitless: when one end's primary is replaced, it moves its transmit onto the fallback SAK (which the peer already receives), and keeps the old primary's receive SA alive (draining) until the peer also moves off it. See §6 for the full rollover walkthrough.

Keeping the fallback *warm* — a live SAK with its receive SA already installed — is what makes the switch gap-free: there is no distribute-then-install round trip at the moment of the switch, because the peer is already able to receive the fallback SAK.

### 2.3 IEEE 802.1X-2020 Justification

| Spec Reference | Requirement | How Satisfied |
| -------------- | ----------- | ------------- |
| §9.14 | "Each KaY shall be capable of maintaining the simultaneous operation of at least two participants" | Two participants (primary + fallback) maintained per KaY |
| §12.1 | Single principal actor controlling the SecY | Exactly one **transmit owner** at a time; the designated primary is preferred (§3.3) |
| §9.5 | MKA Life Time delay before successor-CAK SAK distribution | A successor CAK waits MKA Life Time before distributing (succession only) |
| §9.9 | AN begins with first AN after last SAK in use | AN allocation considers the SAKs held by every participant |
| §9.10 | Only principal installs SAs to SecY | **Deviation (receive-only)** — every participant installs receive SAs; transmit stays single-principal (see §7.1) |
| §9.8 | Only the principal's Key Server distributes a SAK | **Deviation** — the fallback distributes its SAK proactively to stay warm (see §7.1) |
| §11.1/§11.11 | MKPDUs transmitted via uncontrolled port | Carried over a plain L2 socket, not via the MACsec data path |
| 802.1AE §7.1.2/§7.1.3 | Multiple SAs per SC via distinct ANs | Shared RxSC with different ANs per participant |

### 2.4 Alternative Considered — Per-CAK Secure Channels

An alternative way to hold two CAKs warm is to give **each CAK its own Secure
Channel** — i.e. two SecYs on the port (primary CAK → SecY-A/SCI-A, fallback
CAK → SecY-B/SCI-B), each running stock single-participant MKA, instead of two
participants sharing one SC. This was considered and rejected.

**The appeal.** Each KaY would have exactly one participant — its own principal
actor — so the §9.8/§9.10 single-principal invariants would be honoured
per-instance with **no deviation**; MKA, rekey, replay and AN management would
all run stock on each SecY.

**Why it was not chosen.** The spec-cleanliness is paid for in places where
SONiC has far less freedom:

- **Single transmit SC per SecY.** A SecY transmits on exactly one SC
  (802.1AE). Two transmit SCs means **two SecYs on one port**, each with a
  distinct SCI that must be explicitly encoded in the SecTAG (SC bit set, +8
  bytes) and provisioned as a second RxSC on the peer.
- **Hardware support.** Two SAs under one SC is the universal MACsec rekey
  path — every PHY/ASIC and the kernel offload support it. Multiple
  **transmit SCs per port** is a scarcer capability; several offload targets
  effectively support a single TX SC. The shared-SC switch reuses the one
  operation the hardware is guaranteed to do hitlessly (a SAK overlap).
- **Transmit cutover becomes a forwarding-plane problem.** With a shared SC the
  switch is an AN flip inside the SecY, invisible to forwarding. With two SecYs
  it becomes re-steering egress from one netdev/SC to another — a bridge / route
  / SAI decision that is much harder to make truly hitless than enabling a
  different TxSA.
- **Larger blast radius.** Shared-SC keeps all new logic in wpa\_supplicant
  (KaY/MKA). Two-SC would spread changes into SAI MACsec modelling, kernel
  netdev steering and the orchestration that selects the egress instance.
- **Interop.** Vendor NOSes (Cisco / Juniper / Arista) realise their warm
  key-chain / fallback-key overlap as **one SCI with multiple ANs**, forced by
  the same single-transmit-SC constraint. Shared-SC therefore matches what
  vendors put on the wire; a two-SC design (two SCIs from one neighbour, two
  active CAs) diverges from the common case and depends on peer support that
  varies by platform.

The shared-SC approach expresses the transmit cutover as the one primitive
MACsec hardware is guaranteed to perform hitlessly — a SAK overlap/rekey —
rather than a netdev switch the hardware may not support, at the cost of a
narrow, receive-only §9.10 deviation (§7.1). The cross-CAK transmit arbitration
that the spec leaves undefined is handled inside the KaY (§3.3) rather than out
of band.

## 3 Detailed Design

### 3.1 KaY Multi-Participant Model

The KaY maintains a list of MKA participants. In PSK mode today exactly one participant exists; this design adds a second participant for the fallback key.

Each participant maintains its own:
- CAK, and the KEK/ICK derived from it
- Peer state (live and potential peers)
- SAK(s)
- Election and role state (whether it is Key Server, whether it has won election, whether it is the principal)

AN allocation is coordinated at the KaY level so the two participants never claim the same Association Number.

### 3.2 Shared Secure Channel Architecture

When the second participant discovers a peer whose SCI matches a Secure Channel already created by the first participant, it **reuses** that RxSC rather than creating a duplicate.

The hardware driver does not distinguish which CAK generated a given SAK — it matches incoming frames by `(SCI, AN)` per 802.1AE §7.1.3. By allocating different ANs to different participants, both participants' SAKs coexist on the same RxSC without conflict.

```
Driver's view (unchanged):
  RxSC[peer_SCI]
    ├── RxSA[AN=0] → SAK from participant A (primary)
    └── RxSA[AN=2] → SAK from participant B (fallback)
```

### 3.3 Transmit-Owner Selection

The KaY selects a single **transmit owner** among the participants. The supported topology is one point-to-point link with one primary and one fallback participant, both facing the same peer with the same actor priority, so their MKA Key Server election always ties. The general IEEE §12.1 priority / SCI / Dist-SAK-recency comparison is therefore unnecessary; selection reduces to:

1. **Eligibility**: not draining, has live peers, has completed election, and holds a SAK to transmit on.
2. **Preference**: among eligible participants, prefer the **designated primary**; otherwise take the fallback. This keeps transmit on the primary in steady state and returns it to the primary once a rotated-in primary is established, using the fallback only while the primary is unusable.
3. **Handover**: the selected owner becomes the principal and adopts transmit on its (warm) SAK. A superseded owner reverts to a warm standby; it is *not* drained by selection — only a CAK being explicitly retired drains (§3.5).

Selection runs after every MKPDU exchange and on participant timer events. For a single-participant (single-CAK) configuration it changes nothing.

### 3.4 AN Allocation (§9.9)

AN allocation considers every participant rather than a simple round-robin counter:

1. Consider the SAKs and active transmit SAs held by all participants
2. Find the maximum AN currently in use
3. Use the next AN after it (wrapping within `max_sa_per_sc`)

This satisfies §9.9: "begin with the first AN following the last SAK in use by any live CA member."

**Hardware guard**: When the standby participant is created, if the hardware reports `max_sa_per_sc < 4` the request is rejected. With two participants each needing SAK-rotation headroom, fewer than 4 ANs would cause AN collisions during normal SAK rekey within either session.

### 3.5 Transmit Ownership and Draining

Exactly one participant is the **transmit owner** at a time. It installs and enables the single transmit SA and drives the CP state machine. The other participant is a warm standby: it holds a live SAK and installed **receive** SAs, but no enabled transmit SA.

**Switching the transmit owner** (e.g. primary CAK rotated away, fallback takes over transmit):

1. The incoming owner enables its TxSA on a free AN. This is a local driver operation — no peer round trip — and it is safe because the peer already has the incoming SAK installed as a receive SA.
2. Transmit moves to the incoming SAK; the outgoing participant stops transmitting.
3. If the outgoing participant's CAK is being retired, it enters the **draining** state: its receive SAs stay installed so a peer that has not yet switched can still be received, but it no longer transmits and is no longer the owner. (A participant that merely loses ownership without its CAK being retired — for example the fallback when transmit returns to a new primary — simply reverts to a warm standby; it does not drain.)
4. After MKA Life Time (§9.3.2) elapses — by which point the peer has moved off the old SAK — the drained participant and its SAs are deleted.

Draining is what makes a **non-simultaneous** rollover hitless: each end switches its transmit independently, and the old SAK remains receivable on both ends until both have switched.

#### 3.5.1 How the peer keeps receiving across a transmit switch

Transmit and receive are independent per direction, so a transmit switch on one device requires **no** "switch now" signal to the peer:

- **Transmit is a local choice.** When device A's primary CAK is drained/removed, A's KaY re-selects the transmit owner (the warm fallback) and drives A's CP to enable the fallback transmit SA and retire the old primary transmit SA. A now encodes frames whose SecTAG carries the fallback SAK's `(SCI, AN)`. The peer is not told to change anything.
- **The peer receives because the RxSA is pre-installed.** B already holds the fallback SAK as an enabled receive SA (the warm dual-SAK invariant), so B's SecY matches the incoming `(SCI, AN)` and decrypts immediately. This is the reason the fallback must be *warm* rather than cold — a cold standby would need a distribute→install round trip at this moment, which is the gap the design removes.
- **The reverse direction is covered by draining.** B has not rolled, so B keeps transmitting the old primary SAK; A keeps the old primary's receive SA installed (draining) until B also rolls, so B→A is never lost.
- **B switches its own transmit only when its own primary is rolled** — symmetrically and independently. There is no dependency on A's timing.

The coordination involved is the ordinary MKA SAK-use signalling, not a special command: each end advertises, per SAK, whether it is receiving and transmitting on it, and a participant only begins transmitting on a SAK once its peers report they are receiving it. Because the fallback was warm-installed on both ends in advance, both already advertise receive for it, so that condition is already met and the transmit switch proceeds without waiting. The per-frame SecTAG `(SCI, AN)` is what actually selects the SAK on the wire.

#### 3.5.2 Session teardown and peer failover

The rollover is non-simultaneous, so the two ends coordinate entirely through ordinary MKA liveness — there is no special "I have rolled" message. When the operator rotates device A's primary CAK:

1. **A goes silent on the old primary.** The drained primary participant stops sending its MKPDUs (but keeps its receive SAs installed). A's transmit has already moved to the warm fallback (§3.5).
2. **B detects the dead session.** B stops receiving A's primary MKPDUs, so after MKA Life Time B's primary participant loses its last live peer. MKA peer liveness *is* the teardown signal — no new mechanism is needed.
3. **B fails over to the fallback.** When a transmit-owner participant loses its last live peer and a warm carrier (the fallback) is available, the KaY hands transmit to it rather than tearing the SecY down — B switches its transmit SA onto the fallback SAK, which A already receives. (With no warm carrier — the single-CAK case — it falls back to the stock teardown.)
4. **The drained primary is retired once the peer has migrated.** A keeps the old primary's receive SA until its peer has moved off it (its live peer list empties) or a safety maximum (3 × MKA Life Time) elapses, then deletes it.

This is what bounds the drain. The old primary's receive SA on A must outlast only **B's own liveness detection plus its switch to the fallback (≈ MKA Life Time)** — *not* the arbitrary operator gap between rotating the two devices. A fixed "MKA Life Time from drain start" timer would be too short if the operator waited longer than MKA Life Time before rotating B; gating retirement on peer migration (bounded by the safety maximum) covers an unbounded operator gap.

Net effect during the window: A→B rides the warm fallback immediately; B→A rides the old primary until B detects the loss and fails over to the fallback, with A's drained receive SA covering that interval. Once B's operator rotates B too, the new primary establishes on both ends and transmit returns to it (designated-primary preference, §3.3).

### 3.6 MKA Life Time Enforcement (§9.5, §9.3.2)

§9.5 is a *succession* provision: a Key Server should not distribute a SAK with a new CAK until MKA Life Time has elapsed, so a member holding both the prior and the new CAK does not lose connectivity. The delay applies only once a prior CAK has already distributed a SAK on this KaY; the very first SAK at initial establishment is not delayed. A successor CAK therefore waits MKA Life Time after it begins participating before distributing its SAK.

The **drain** timer in §3.5/§3.5.2 also derives from MKA Life Time (per §9.3.2 the old participant is retained at least that long), but is gated on the peer having migrated off the old SAK and bounded by a safety maximum of 3 × MKA Life Time, so it covers an unbounded operator gap rather than a fixed interval from drain start.

### 3.7 SA Install Model and the §9.10 Deviation

Strict §9.10 states that only the principal actor installs SAs to the SecY. The warm dual-SAK design **deviates from this on the receive side only**:

| SA type | Who installs | Conformance |
| ------- | ------------ | ----------- |
| **Receive SAs** | **every established participant** installs a receive SA for its own SAK on the shared RxSCs | **Deviation** — §9.10 expects only the principal to install |
| **Transmit SA** | only the principal / transmit owner installs and enables the one transmit SA | Conformant — transmit stays single-principal |

The deviation is deliberate and narrow:

- It is **receive-only**. Receiving on an additional SAK is purely additive — it cannot cause the partial connectivity that §9.10 exists to prevent (that risk comes from *transmitting* on a SAK a peer cannot receive, which this design never does).
- It mirrors the same-CAK SAK rekey overlap that MKA already performs (two receive SAs briefly coexist), made **continuous** and extended **across CAKs**.
- It is the minimum required to absorb non-simultaneous CAK updates: the fallback receive SA must already be installed on both ends *before* either end changes its primary, which is impossible to arrange on-demand.

To support this, two further behaviours differ from stock single-participant operation:

- **Proactive SAK distribution**: each instance's elected Key Server distributes its SAK regardless of principal status, so both the primary and fallback hold a live SAK (stock code distributes only for the principal).
- **Per-participant receive install**: the received/own SAK is installed as a receive SA by the owning participant, decoupled from the single transmit owner (stock code installs all SAs only for the principal via the CP).

See the Spec Deviations section for the consolidated list and rationale.

### 3.8 Controlled Port State Machine Interaction

The Controlled Port (CP) state machine is a single per-KaY instance, not per-participant. Every CP-driven SecY operation (create/delete/enable of transmit and receive SAs) acts on the participant currently marked as the principal — the transmit owner. The CP therefore always acts on **one** participant. The warm dual-SAK changes are designed to preserve that single-owner contract rather than extend the CP itself.

**Ownership invariant.** At most one participant is the principal at any time the CP runs. The CP is never made aware of the standby participant; its view of the world is unchanged from stock single-participant operation.

How the new behaviours respect this:

- **Standbys bypass the CP entirely.** A warm standby installs its receive SA directly, not through the CP. It never becomes the principal, so the CP can never resolve to it. Receiving is purely additive (see §3.7) and involves no CP transition.
- **Transmit ownership changes are atomic from the CP's perspective.** Every handover path — return-to-primary, drain, and peer-failover — clears the outgoing owner's principal status (and disables its transmit SA) *before* marking the new owner and driving the CP to adopt transmit. There is no window in which two participants are the principal, so the CP can never resolve to the wrong participant mid-handover.
- **Transmit switching is deterministic.** The outgoing owner's transmit SA is explicitly disabled during handover, leaving exactly one enabled transmit SA, rather than relying on driver-specific "encoding SA" selection.

**Single-CAK behaviour is unchanged.** When only one CAK is configured the owner-selection logic short-circuits, the single participant is the principal, and the CP is driven exactly as in stock wpa\_supplicant.

The net effect is that the CP continues to operate as a single-principal state machine; the warm design coordinates *which* participant is the principal around it, without ever presenting it with two simultaneous owners.

## 4 Config DB Schema

No Config DB changes are required. The existing `MACSEC_PROFILE` table already includes the necessary fields:

```rfc5234
MACSEC_PROFILE|{{profile}}
    "primary_cak":{{primary_cak}}
    "primary_ckn":{{primary_ckn}}
    "fallback_cak":{{fallback_cak}} (OPTIONAL)
    "fallback_ckn":{{fallback_ckn}} (OPTIONAL)
```

MACsec Mgr maps these to the wpa\_supplicant configuration as follows:

| Config DB Field | wpa\_supplicant Field | Description |
| --------------- | --------------------- | ----------- |
| `primary_cak` | `mka_cak` | Primary Connectivity Association Key |
| `primary_ckn` | `mka_ckn` | Primary CAK Name |
| `fallback_cak` | `mka_cak2` | Fallback Connectivity Association Key |
| `fallback_ckn` | `mka_ckn2` | Fallback CAK Name |

## 5 wpa\_supplicant Changes

### 5.1 Configuration File

New network block fields for the fallback key:

```
network={
    key_mgmt=NONE
    eapol_flags=0
    macsec_policy=1
    mka_cak=<primary_cak_hex>
    mka_ckn=<primary_ckn_hex>
    mka_cak2=<fallback_cak_hex>
    mka_ckn2=<fallback_ckn_hex>
}
```

When both `mka_cak2` and `mka_ckn2` are present, wpa\_supplicant creates two participants: the primary (principal) and the fallback (standby).

If only the primary key is configured, behavior is identical to the unmodified codebase.

### 5.2 Runtime Key Management (wpa\_cli)

#### Add a new key at runtime

```bash
wpa_cli -i <iface> mka_add_key cak=<cak_hex> ckn=<ckn_hex>
```

Creates a new MKA participant with the given CAK/CKN. The participant starts as a warm standby (not the transmit owner) and begins MKPDU exchange with the peer. Once the peer configures the same key and live peers are established, it becomes eligible to be selected as the transmit owner (§3.3).

#### Delete a key at runtime

```bash
wpa_cli -i <iface> mka_del_key ckn=<ckn_hex>
```

Deletes the MKA participant matching the given CKN. If this was the principal participant, transmit ownership automatically transfers to the remaining eligible participant (§3.3).

#### Update (replace) a key at runtime

```bash
wpa_cli -i <iface> mka_update_key old_ckn=<old_ckn_hex> cak=<new_cak_hex> ckn=<new_ckn_hex>
```

Replaces an existing MKA participant: it deletes the participant matching `old_ckn`, then creates a new participant with the given `cak`/`ckn`. This is the preferred way to rotate either key while the other is active. The operation is **not atomic** — the old participant is removed first so its Association Numbers are freed before the replacement claims one (triggering SecY transfer if it was principal), then the new participant is created in standby mode.

Before the destructive delete, the handler validates the request: `old_ckn` must match an existing participant, and the new `ckn` must not collide with a different existing participant. The new CKN must differ from the one it replaces (wpa\_supplicant rejects duplicate CKNs). If the create fails after the delete, the session continues on the other (fallback) participant, so a fallback must be established before rotating the primary.

**Precondition**: the key being replaced must not be the sole active principal — a standby participant with live peers must exist to absorb SecY ownership. In practice: rotate the standby/fallback key while the primary is active, or use the primary rollover flow (§6.2) for the primary.

### 5.3 Status Output

```bash
wpa_cli -i <iface> status
```

The KaY appends a per-participant section to the interface status, one block per participant:

```
participant_idx=0
ckn=<ckn_hex>
mi=<mi_hex>
mn=<mn>
active=yes
participant=yes
retain=no
live_peers=1
potential_peers=0
is_key_server=yes
is_elected=yes
transmit_owner=yes
warm_rx=yes
primary_slot=yes
draining=no
participant_idx=1
ckn=<ckn_hex>
...
live_peers=1
is_key_server=no
is_elected=no
transmit_owner=no
warm_rx=yes
primary_slot=no
draining=no
```

The `ckn` and `live_peers` fields are what MACsec Mgr uses to evaluate rotation preconditions (companion HLD). `transmit_owner` (the participant driving the transmit SA), `warm_rx` (receive SAs installed), `primary_slot` (the designated primary), and `draining` expose the warm dual-SAK per-participant state.

## 6 Operational Flows

### 6.1 Initial Setup with Backup Key

```
Operator                    wpa_supplicant (Switch A)              wpa_supplicant (Switch B)
   │                               │                                       │
   │  Config: primary_cak,         │                                       │
   │  primary_ckn,                 │                                       │
   │  fallback_cak,                │                                       │
   │  fallback_ckn                 │                                       │
   │──────────────────────────────>│                                       │
   │                               │  Create participant_A (primary, principal)
   │                               │  Create participant_B (fallback, standby)
   │                               │                                       │
   │                               │──── MKPDUs (CKN_A) ─────────────────>│
   │                               │<─── MKPDUs (CKN_A) ──────────────────│
   │                               │  participant_A: live peers established │
   │                               │  participant_A distributes SAK_A      │
   │                               │  SAK_A installed (AN=0)               │
   │                               │                                       │
   │                               │──── MKPDUs (CKN_B) ─────────────────>│
   │                               │<─── MKPDUs (CKN_B) ──────────────────│
   │                               │  participant_B: live peers established │
   │                               │  participant_B distributes SAK_B,     │
   │                               │  installs RxSA (AN=2) — warm standby   │
   │                               │                                       │
   │                               │  Steady state: transmit on SAK_A;     │
   │                               │  SAK_A (AN=0) and SAK_B (AN=2) both    │
   │                               │  installed for receive on both ends   │
```

### 6.2 Hitless Primary Key Rollover (non-simultaneous)

The two ends are updated at different times. Throughout, the **fallback** SAK (unchanged, installed on both ends) carries traffic during the window where the ends do not share the same primary.

```
        Switch A                         Switch B
   primary=CAK_P (tx)              primary=CAK_P (tx)
   fallback=CAK_F (rx warm)        fallback=CAK_F (rx warm)
   ── both transmit on SAK_P; SAK_P and SAK_F installed rx on both ──

 t1: operator updates A's primary CAK_P → CAK_P'
   A: new primary CAK_P' has no peer yet (B not updated) → cannot establish
   A: move transmit OFF SAK_P onto SAK_F   ──────────► B already has SAK_F rx → OK
   A: drain old primary — keep SAK_P rx installed (B still transmits SAK_P)
   B: still transmits SAK_P ───────────────────────►  A still has SAK_P rx → OK
   ── A transmits SAK_F, B transmits SAK_P; both receivable both ends → no loss ──

 t2: operator updates B's primary CAK_P → CAK_P'
   B: move transmit OFF SAK_P onto SAK_F   ──────────► A already has SAK_F rx → OK
   B: drain old primary (keep SAK_P rx for MKA Life Time)
   ── both transmit SAK_F (fallback) ──
   A and B now share CAK_P' → new primary establishes, distributes SAK_P'',
   installs RxSA on both ends at a free AN (warm)

 t3: transmit returns to the new primary
   A, B: move transmit SAK_F → SAK_P''  (peer already has SAK_P'' rx) → hitless
   drained old-primary participants deleted after MKA Life Time
   ── steady state restored: transmit on SAK_P''; SAK_P'' and SAK_F warm ──
```

The transmit owner returns to the **primary slot** (designated-primary preference, §3.5/§8) once the new primary is warm, so the fallback goes back to standby rather than remaining the active key.

### 6.3 Hitless Fallback Key Update

The fallback key can be rotated at any time while the primary key is active.
Use `mka_update_key` for an in-place replacement:

```
Operator                    wpa_supplicant
   │                               │
   │  mka_update_key               │
   │    old_ckn=<old_fallback_ckn> │
   │    cak=<new_cak>              │
   │    ckn=<new_ckn>              │
   │──────────────────────────────>│  1. Delete old standby participant
   │                               │     (principal unaffected)
   │                               │  2. Create new standby participant
   │                               │     MKPDU exchange begins
   │                               │  New fallback ready once
   │                               │  peer configures matching key
```

Alternatively, the two-step `mka_del_key` + `mka_add_key` sequence achieves the same result but with a window where no fallback key exists.

**Full key rotation lifecycle** (both primary and fallback rotated):

```
Time   Operation                         Active    Standby
─────  ──────────────────────────────    ─────── ──────────
T0     Initial state                      CAK_A    CAK_B
T1     mka_update_key (replace CAK_B      CAK_A    CAK_B'
         with CAK_B')
       (wait for peer to configure CAK_B')
T2     mka_del_key CAK_A                  CAK_B'   (none)
         → CAK_B' becomes principal
T3     mka_add_key CAK_A'                 CAK_B'   CAK_A'
         → new primary created as standby
       (wait for peer to configure CAK_A')
T4     mka_del_key CAK_B'                 CAK_A'   (none)
         → CAK_A' becomes principal
T5     mka_add_key CAK_B''                CAK_A'   CAK_B''
         → new fallback ready
       Both keys fully rotated. Zero traffic loss.
```

### 6.4 Emergency Key Revocation

If a key is compromised, the operator can immediately delete it:

```bash
wpa_cli -i <iface> mka_del_key ckn=<compromised_ckn>
```

If this was the principal, the remaining participant takes over immediately. There may be a brief traffic disruption if the backup participant hasn't yet established live peers — this is by design (security > availability for compromised keys).

## 7 IEEE Spec Conformance

**Conformance is judged on externally observable behaviour, not internal structure.** Both IEEE Std 802.1X-2020 (§5) and IEEE Std 802.1AE-2018 (§5) define a conformance claim as a claim about a system's behaviour "as revealed through externally observable behaviour" — the protocol on the wire (MKPDU format and procedures) and the MACsec data-plane service — not about a particular implementation. The state machines in these standards, including the CP state machine and the single-principal-actor rule that governs which participant installs SAs to the SecY, are a **normative model for specifying that observable behaviour**, not a mandated code structure. An implementation organised differently internally is conformant provided its observable behaviour is identical; 802.1AE says this directly for frame processing ("Implementations can process frames as convenient, provided the externally observable result is the same", §10.6.5) and, for a KaY that runs multiple participants, in Annex E ("Conformance to this standard remains strictly in terms of externally observable behaviour and does not depend on any implementation suggestion in this Annex").

This is the lens for the deviations below. The warm dual-SAK design keeps the CP a single-principal state machine and reorganises *around* it — driving it only from the transmit owner, and installing the warm receive SAs through a direct path rather than the modelled principal path (§3.8). The resulting observable behaviour is exactly what the single-principal model exists to produce: one transmit SA at a time, well-formed MKPDUs per CKN, and frames only ever sent on a SAK the peer can already receive. The two departures are from the *internal model*, not from the behaviour the standard actually tests:

- The **§9.10** departure (a non-principal participant installing a receive SA) is **entirely local** — invisible to the peer and to the data plane except as one extra, already-distributed SAK that can be received.
- The **§9.8** departure (the fallback distributing its SAK while non-principal) is observable only as a **well-formed Distributed SAK in a valid MKPDU** for an established CA — ordinary MKA behaviour; only an internal sequencing rule differs, never the wire encoding.

Multi-participant operation is itself anticipated by the standard: 802.1X-2020 §9.14 requires a KaY to support at least two simultaneous participants. The design stays within that envelope, so the CP/principal-actor "deviations" are best read as a permitted internal reorganisation rather than a break from the standard's observable requirements.

| Spec Reference | Clause | Status | Notes |
| -------------- | ------ | ------ | ----- |
| 802.1X-2020 §9.14 | ≥2 simultaneous participants per KaY | ✅ Conformant | KaY maintains primary and fallback participants concurrently |
| 802.1X-2020 §12.1 | Principal actor selection | ✅ Conformant | single transmit owner; designated-primary preference |
| 802.1X-2020 §9.5 | MKA Life Time before successor-CAK SAK distribution | ✅ Conformant | a successor CAK waits MKA Life Time before distributing |
| 802.1X-2020 §9.3.2 | Retain old participant ≥ MKA Life Time | ✅ Conformant | the old primary is drained in place and retired only after the peer migrates off it (§3.5), never deleted immediately |
| 802.1X-2020 §9.9 | AN follows last in-use AN | ✅ Conformant | AN allocation accounts for the SAKs held by every participant |
| 802.1X-2020 §9.8 | Only the principal/Key Server distributes a SAK | ⚠️ **Deviation** | non-principal instances distribute their SAK proactively to keep the fallback warm (see Spec Deviations) |
| 802.1X-2020 §9.10 | Only principal installs SAs | ⚠️ **Deviation (receive-only)** | every participant installs **receive** SAs; transmit stays single-principal (see Spec Deviations) |
| 802.1X-2020 §11.1/§11.11 | MKPDUs via uncontrolled port | ✅ Conformant | L2 socket, not via MACsec datapath |
| 802.1AE-2018 §7.1.2/§7.1.3 | Multiple SAs per SC | ✅ Conformant | Shared RxSC, distinct ANs |

### 7.1 Spec Deviations

These deliberate deviations are required to achieve hitless CAK rollover across **non-simultaneously** updated peers. They are the minimum departure from a strict reading of IEEE 802.1X-2020 and are confined so as not to weaken MACsec's security or connectivity guarantees.

1. **§9.10 — receive-side SA installation by non-principal participants.**
   *Strict text*: only the principal actor installs SAs to the SecY.
   *Deviation*: every established participant installs a **receive** SA for its own SAK on the shared RxSCs, so both the primary and fallback SAKs are continuously receivable on both ends. The **transmit** SA is still installed only by the single principal (transmit owner).
   *Why it is safe*: the deviation is receive-only and purely additive. §9.10 exists to prevent a Key Server from selecting MACsec protection that some members cannot receive (partial connectivity). That risk arises only from *transmitting* on a SAK a peer lacks — which this design never does. Receiving on an extra, already-distributed SAK cannot cause it.
   *Why it is required*: to absorb a non-simultaneous primary CAK change, the fallback receive SA must already be installed on both ends before either end switches. On-demand installation at switch time is impossible (it needs a peer round trip the peer has not been told to start), so the fallback must be kept warm.

2. **§9.8 — proactive SAK distribution for non-principal instances.**
   *Strict text*: the Key Server (of the principal actor's instance) generates and distributes the SAK.
   *Deviation*: the elected Key Server of the fallback instance also distributes its SAK while non-principal, so the fallback holds a live SAK to install as the warm receive SA above.
   *Why it is safe*: SAK distribution is authenticated and confidential under each instance's own CAK/KEK; distributing a fallback SAK does not expose it to anyone not already holding the fallback CAK. No member is forced to *use* the fallback SAK for transmit until a rollover selects it.

3. **Boundedness and hardware**: both deviations are only meaningful when a fallback is configured, require `max_sa_per_sc >= 4`, and collapse to exact stock behaviour for a single-key configuration (one participant, one SAK, no extra receive SA).

## 8 Implementation Outline

All changes are within the `sonic-wpa-supplicant` repository. Single-key (no fallback) configurations are unaffected.

### 8.1 Components Touched

| Component | What changed |
| --------- | ------------ |
| Configuration layer | Parse and persist the fallback key (`mka_cak2` / `mka_ckn2`) |
| Control interface / CLI | The runtime `mka_add_key` / `mka_del_key` / `mka_update_key` commands, with validation and the carrier guards |
| KaY / MKA core | The second participant, shared RxSC reuse, AN allocation across participants (§9.9), §9.5 succession gating, and all of the warm dual-SAK behaviour below |

### 8.2 Warm Dual-SAK Behaviours

The following behaviours were added to the KaY:

- **Proactive SAK distribution** — the fallback's Key Server distributes its SAK even while it is not the principal, so the fallback always holds a live SAK.
- **Per-participant receive install** — each participant installs a receive SA for its own SAK on the shared RxSC, so both SAKs are continuously receivable.
- **Transmit-owner model and handover** — exactly one participant transmits at a time; ownership is handed over to the warm fallback (and back to a re-established primary) without a peer round trip.
- **Draining** — a CAK being retired stops transmitting and goes silent, but keeps its receive SAs until the peer migrates off it, then is deleted (bounded by a 3 × MKA Life Time safety maximum).
- **Peer failover on session loss** — a transmit owner that loses its last live peer hands transmit to the warm fallback rather than tearing the SecY down (single-CAK still tears down as stock).
- **Designated-primary preference** — transmit returns to the primary once it is re-established and warm.
- **Drain-aware key update with carrier guards** — a primary rotation drains the old primary in place; both primary and fallback rotations are rejected unless another participant can carry traffic.
- **Status / observability** — per-participant transmit-owner, warm-receive, primary, and draining state is exposed in `status`.

The per-participant receive install and the transmit-owner handover are the key integration points, because they touch the boundary between per-participant SAK bookkeeping and the single KaY-level CP state machine (§3.8). MACsec Mgr is unchanged — the drain-vs-delete decision is made inside wpa\_supplicant.

## 9 Testing

### 9.1 Unit Tests

| Test Case | Description |
| --------- | ----------- |
| Single-key backward compat | Configure only `mka_cak`/`mka_ckn`; verify identical behavior to unmodified code |
| Dual-key startup | Configure both primary and fallback; verify two participants created, only one principal |
| Runtime key add | `mka_add_key` creates standby participant; verify MKPDU exchange |
| Runtime key delete (standby) | `mka_del_key` on standby; verify principal unaffected |
| Runtime key delete (transmit owner) | `mka_del_key` on the transmit owner; verify transmit hands over to the warm fallback |
| Runtime key update (invalid) | `mka_update_key` with non-existent `old_ckn`; verify error returned, no state change |
| Update primary rotation | `mka_update_key` replacing the primary drains it in place and creates the new primary as the primary slot; verify old primary's RxSA retained, transmit on fallback, then returns to new primary |
| Update carrier guard (primary) | `mka_update_key` on the primary with no established fallback; verify rejected, live session untouched |
| Update carrier guard (fallback) | `mka_update_key` on the fallback while the primary is not active; verify rejected |
| AN allocation | With two participants holding different ANs, verify the next AN is chosen without collision |
| MKA Life Time | Successor CAK cannot distribute its SAK before MKA Life Time elapses |
| Shared RxSC | Verify second participant reuses first's RxSC rather than creating duplicate |
| Primary-slot preference | With primary and fallback both eligible, verify the primary slot is the transmit owner |
| max\_sa\_per\_sc < 4 rejected | Attempt `mka_add_key` on hardware reporting 2 ANs; verify error returned, no standby created |

### 9.2 VS (Virtual Switch) Tests

End-to-end tests using veth pairs or KVM-based virtual switches:

| Test Case | Description |
| --------- | ----------- |
| Hitless primary rollover (non-simultaneous) | Ping continuously; change primary CAK on the two ends **at different times**; verify zero loss with traffic riding the fallback during the window |
| Warm-standby receive | Verify the fallback SAK is installed as a receive SA on both ends at steady state (two RxSAs at distinct ANs) before any rollover |
| Peer failover on session loss | Roll the primary on one end only; verify the peer loses the primary live peer, fails over its transmit to the fallback, and traffic continues both ways |
| Drain retirement | After a primary roll, verify the old primary's receive SA is retained until the peer migrates off it (bounded by the 3 × MKA Life Time safety maximum), then deleted — including when the second end is rolled long after the first |
| Return to primary slot | After the new primary establishes on both ends, verify transmit returns from fallback to the primary slot |
| Hitless fallback update | Ping continuously; replace fallback key via `mka_update_key`; verify zero packet loss |
| Simultaneous rollover | Both sides change primary simultaneously; verify recovery via fallback |
| Key revocation | Delete principal without fallback established; verify graceful degradation |

## 10 Limitations and Future Work

1. **MACsec Mgr integration**: the Config DB orchestration that maps `primary_*`/`fallback_*` changes to runtime commands is specified in the [MACsec Key Rotation via Config DB HLD](./macsec-key-rotation-configdb-hld.md).

2. **Maximum participants**: the design supports exactly 2 concurrent participants (primary + fallback). The warm steady state uses 2 ANs and a rollover up to 4, so `max_sa_per_sc >= 4` is mandatory and N > 2 participants is not supported.

3. **EAP/802.1X mode**: targets PSK (pre-shared key) mode only. EAP-based MACsec has its own key hierarchy and does not use this mechanism.

4. **Spec deviations**: the design knowingly deviates from a strict reading of §9.10 and §9.8 (see §7.1). Deployments requiring strict §9.10 conformance must not enable a fallback key; single-key operation is fully conformant.
