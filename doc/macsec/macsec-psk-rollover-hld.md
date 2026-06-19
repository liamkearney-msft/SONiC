<!-- omit in toc -->
# MACsec PSK/CAK Rollover — High Level Design Document

***Revision***

|  Rev  |    Date    |     Author     | Change Description |
| :---: | :--------: | :------------: | ------------------ |
|  0.1  | 2025-06-09 | Liam Kearney   | Initial version    |

<!-- omit in toc -->
## Table of Contents

- [About this Manual](#about-this-manual)
- [Scope of this Document](#scope-of-this-document)
- [Abbreviation](#abbreviation)
- [1 Requirements Overview](#1-requirements-overview)
  - [1.1 Functional Requirements](#11-functional-requirements)
  - [1.2 Hardware Requirements](#12-hardware-requirements)
  - [1.3 Non-Functional Requirements](#13-non-functional-requirements)
- [2 Design Overview](#2-design-overview)
  - [2.1 Problem Statement](#21-problem-statement)
  - [2.2 Approach — Shared-SC Warm Standby](#22-approach--shared-sc-warm-standby)
  - [2.3 IEEE 802.1X-2020 Justification](#23-ieee-8021x-2020-justification)
- [3 Detailed Design](#3-detailed-design)
  - [3.1 KaY Multi-Participant Model](#31-kay-multi-participant-model)
  - [3.2 Shared Secure Channel Architecture](#32-shared-secure-channel-architecture)
  - [3.3 Principal Actor Selection (§12.1)](#33-principal-actor-selection-121)
  - [3.4 AN Allocation (§9.9)](#34-an-allocation-99)
  - [3.5 SecY Ownership Transfer](#35-secy-ownership-transfer)
  - [3.6 MKA Life Time Enforcement (§9.5)](#36-mka-life-time-enforcement-95)
  - [3.7 SA Install Gating (§9.10)](#37-sa-install-gating-910)
- [4 Config DB Schema](#4-config-db-schema)
- [5 wpa\_supplicant Changes](#5-wpa_supplicant-changes)
  - [5.1 Configuration File](#51-configuration-file)
  - [5.2 Runtime Key Management (wpa\_cli)](#52-runtime-key-management-wpa_cli)
  - [5.3 Status Output](#53-status-output)
- [6 Operational Flows](#6-operational-flows)
  - [6.1 Initial Setup with Backup Key](#61-initial-setup-with-backup-key)
  - [6.2 Hitless Primary Key Rollover](#62-hitless-primary-key-rollover)
  - [6.3 Hitless Fallback Key Update](#63-hitless-fallback-key-update)
  - [6.4 Emergency Key Revocation](#64-emergency-key-revocation)
- [7 IEEE Spec Conformance](#7-ieee-spec-conformance)
- [8 Files Changed](#8-files-changed)
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
| SC           | Secure Channel                           |
| SCI          | Secure Channel Identifier                |
| SecY         | MACsec Security Entity                   |
| XPN          | Extended Packet Numbering                |

## 1 Requirements Overview

### 1.1 Functional Requirements

1. **Dual CAK/CKN support**: Two pre-shared keys (primary + fallback) can be configured per interface, either at startup or at runtime.
2. **Hitless rollover**: When the primary CAK is revoked/replaced, traffic continues uninterrupted by automatically falling through to the fallback key's pre-established MKA session.
3. **Independent key lifecycle**: Each key (primary, fallback) can be added, replaced, or removed independently via `wpa_cli` at runtime.
4. **Zero-gap failover**: Both MKA sessions share Receive SCs, so SAKs from both keys can coexist in hardware — the transition between keys does not drop packets.
5. **IEEE 802.1X-2020 conformance**: Multi-participant operation complies with §9.14 (≥2 participants), §12.1 (principal selection), §9.9 (AN allocation), §9.5 (MKA Life Time), and §9.10 (SA install gating).

### 1.2 Hardware Requirements

1. **`max_sa_per_sc >= 4`**: The ASIC/PHY must support all 4 Association Numbers (ANs 0–3) per Secure Channel. With two concurrent MKA participants, each session needs at least 2 ANs (current SAK + rollover headroom). If the hardware reports `max_sa_per_sc < 4`, wpa\_supplicant will reject standby participant creation with an error. Most modern MACsec ASICs support 4 ANs; the 2-AN limit is mainly found on older or basic MACsec-capable NICs.

### 1.3 Non-Functional Requirements

1. **Minimal code changes**: The implementation leverages existing multi-participant infrastructure (`participant_list` is already a `dl_list`) rather than adding parallel data structures.
2. **Backward compatibility**: A single-key configuration (no `mka_cak2`/`mka_ckn2`) behaves identically to the unmodified codebase.
3. **No downstream changes required**: MACsec Mgr, MACsec Orch, SAI, and kernel driver are unaware of the change — they see normal SA create/delete operations.

## 2 Design Overview

### 2.1 Problem Statement

MACsec with PSK requires both endpoints to share the same CAK/CKN. Rotating this key today requires:

1. Disable MACsec on both ends
2. Configure the new key
3. Re-enable MACsec

This causes a traffic outage proportional to the MKA negotiation time (typically 3–6 seconds). In production networks, this is unacceptable for links carrying critical traffic.

### 2.2 Approach — Shared-SC Warm Standby

The design runs **two MKA participants** within a single KaY — one per CAK/CKN pair. Both participants exchange MKPDUs independently, but only one (the **principal**) drives the SecY (installs TxSA, signals CP).

The key insight is that **Receive SCs are shared** between participants. When the peer has the same SCI regardless of which CAK generated the SAK, both participants' SAKs are installed as RxSAs on the same RxSC at different ANs. This mirrors normal intra-session SAK rollover (which is already hitless) but across CAK boundaries.

```
KaY (one per interface)
├── Participant A (primary CAK)    ← principal, secy_installed=true
│   ├── Sends MKPDUs with CKN_A
│   ├── TxSC → TxSA[AN=0, SAK_A]
│   └── RxSC[peer] → RxSA[AN=0, SAK_A]    ← shared RxSC
│
├── Participant B (fallback CAK)   ← standby, secy_installed=false
│   ├── Sends MKPDUs with CKN_B
│   ├── No TxSC (standby)
│   └── RxSC[peer] → RxSA[AN=2, SAK_B]    ← same shared RxSC
│
└── SecY driver sees: one TxSC, one RxSC, multiple RxSAs at different ANs
```

When Participant A's key is revoked, Participant B becomes principal, creates its own TxSC, and traffic continues using SAK\_B which was already installed in hardware.

### 2.3 IEEE 802.1X-2020 Justification

| Spec Reference | Requirement | How Satisfied |
| -------------- | ----------- | ------------- |
| §9.14 | "Each KaY shall be capable of maintaining the simultaneous operation of at least two participants" | Two participants on `participant_list` |
| §12.1 | Single principal actor selection among participants | `enforce_single_principal()` with priority + Dist-SAK recency algorithm |
| §9.5 | MKA Life Time delay before new-CAK SAK distribution | `started_participating` timer check |
| §9.9 | AN begins with first AN after last SAK in use | `ieee802_1x_kay_next_an()` scans all participants |
| §9.10 | Only principal installs SAs to SecY | `secy_installed` gates on all CP signal paths |
| §11.1/§11.11 | MKPDUs transmitted via uncontrolled port | L2 socket at `ETH_P_EAPOL` — not via MACsec |
| 802.1AE §7.1.2/§7.1.3 | Multiple SAs per SC via distinct ANs | Shared RxSC with different ANs per participant |

## 3 Detailed Design

### 3.1 KaY Multi-Participant Model

The existing `struct ieee802_1x_kay` has a `participant_list` (`dl_list`). Today, PSK mode creates exactly one participant. This design adds a second participant for the fallback key.

Each participant maintains its own:
- CAK, KEK, ICK (derived from its own CAK/CKN)
- Peer lists (`live_peers`, `potential_peers`)
- SAK list
- Election state (`is_key_server`, `is_elected`, `principal`)

The KaY-level `dist_an` counter is shared, ensuring AN allocation across participants never collides.

### 3.2 Shared Secure Channel Architecture

When a second participant discovers a peer whose SCI matches an existing RxSC created by the first participant, it **reuses** that RxSC rather than creating a duplicate. This is tracked by the helper function `ieee802_1x_kay_is_shared_receive_sc()`.

The hardware driver does not distinguish which CAK generated a given SAK — it matches incoming frames by `(SCI, AN)` per 802.1AE §7.1.3. By allocating different ANs to different participants, both participants' SAKs coexist on the same RxSC without conflict.

```
Driver's view (unchanged):
  RxSC[peer_SCI]
    ├── RxSA[AN=0] → SAK from participant A (primary)
    └── RxSA[AN=2] → SAK from participant B (fallback)
```

### 3.3 Principal Actor Selection (§12.1)

The `enforce_single_principal()` function implements IEEE 802.1X-2020 §12.1:

1. **Eligibility**: Must have live peers (`dl_list_empty(&p->live_peers) == false`) and completed election (`p->is_elected == true`)
2. **Priority**: Among eligible candidates, prefer the one whose elected Key Server has higher priority (lower numeric value)
3. **Tiebreaker**: Most recently received Dist-SAK (highest key number `kn`)
4. **Transfer**: The selected participant gets `secy_installed = true`; all others get `secy_installed = false` and `principal = false`

This function is called after every MKPDU decode cycle (`ieee802_1x_kay_decode_mkpdu()`).

### 3.4 AN Allocation (§9.9)

The `ieee802_1x_kay_next_an()` function replaces the simple `dist_an++` round-robin:

1. Scan all participants' SAK lists and active TxSAs
2. Find the maximum AN currently in use
3. Return `(max_an + 1) % max_sa_per_sc`

This ensures compliance with §9.9: "begin with the first AN following the last SAK in use by any live CA member."

**Hardware guard**: At standby participant creation, if `kay->max_sa_per_sc < 4`, the request is rejected. With two participants each needing SAK rotation headroom, fewer than 4 ANs would cause AN collisions during normal SAK rollover within either session.

### 3.5 SecY Ownership Transfer

When the principal changes (e.g., old participant deleted, new one becomes principal):

1. The new principal creates its own TxSC via `secy_cp_on_new_sa()`
2. RxSCs are already shared — no RxSC creation needed
3. The new principal's CP state machine takes over SecY signaling
4. Old TxSAs are cleaned up during normal SA lifecycle

The `secy_installed` flag acts as the ownership token:
- Gates SAK installation to hardware (`ieee802_1x_mka_decode_dist_sak_body`)
- Gates CP state machine signals (`ieee802_1x_kay_elect_key_server`)
- Gates new SAK generation (`ieee802_1x_participant_timer`)

### 3.6 MKA Life Time Enforcement (§9.5)

Each participant tracks `started_participating` (set at creation time). Before distributing a SAK, the participant checks:

```c
if ((time(NULL) - participant->started_participating) < MKA_LIFE_TIME / 1000)
    return -1;  /* Too soon — wait for MKA Life Time to elapse */
```

This prevents a newly-added backup key from immediately trying to distribute a SAK before peer reachability is confirmed.

When deleting an old participant during rollover, a warning is logged if MKA Life Time hasn't elapsed since the last SAK distribution. The deletion is not blocked (the operator may have valid reasons) but the warning aids debugging.

### 3.7 SA Install Gating (§9.10)

Per §9.10, only the principal actor may install SAs to the SecY. All SA installation paths are gated on `participant->secy_installed`:

| Code Path | Gate |
| --------- | ---- |
| `ieee802_1x_mka_decode_dist_sak_body()` — received SAK processing | `if (participant->secy_installed)` before CP signals |
| `ieee802_1x_kay_elect_key_server()` — election result CP signal | `if (participant->secy_installed)` before `ieee802_1x_cp_signal_newsak()` |
| `ieee802_1x_participant_timer()` — periodic SAK generation | `if (!participant->secy_installed) return` |

Standby participants record received SAKs in their `sak_list` (for later use if promoted) but do not signal the CP or install SAs to the driver.

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

When both `mka_cak2` and `mka_ckn2` are present, `ieee802_1x_create_preshared_mka()` creates two participants: the primary (principal) and the fallback (standby).

If only the primary key is configured, behavior is identical to the unmodified codebase.

### 5.2 Runtime Key Management (wpa\_cli)

#### Add a new key at runtime

```bash
wpa_cli -i <iface> mka_add_key <cak_hex> <ckn_hex>
```

Creates a new MKA participant with the given CAK/CKN. The participant starts in standby mode (not principal) and begins MKPDU exchange with the peer. Once the peer configures the same key and live peers are established, the participant becomes eligible for principal selection.

#### Delete a key at runtime

```bash
wpa_cli -i <iface> mka_del_key <ckn_hex>
```

Deletes the MKA participant matching the given CKN. If this was the principal participant, SecY ownership automatically transfers to the remaining eligible participant via `enforce_single_principal()`.

#### Update (replace) a key at runtime

```bash
wpa_cli -i <iface> mka_update_key old_ckn=<old_ckn_hex> cak=<new_cak_hex> ckn=<new_ckn_hex>
```

Atomically replaces an existing MKA participant: deletes the participant matching `old_ckn`, then creates a new participant with the given `cak`/`ckn`. This is the preferred way to rotate either key while the other is active. The old participant is removed first (triggering SecY transfer if it was principal), then the new participant is created in standby mode.

**Precondition**: The key being replaced must NOT be the active principal, or if it is, a standby participant with live peers must exist to absorb SecY ownership. In practice: always rotate the standby/fallback key first, or use the hitless primary rollover flow (§6.2) for the primary.

### 5.3 Status Output

```bash
wpa_cli -i <iface> status
```

Reports per-participant status:

```
mka_participant_0_ckn=<ckn_hex>
mka_participant_0_principal=true
mka_participant_0_secy_installed=true
mka_participant_0_live_peers=1
mka_participant_1_ckn=<ckn_hex>
mka_participant_1_principal=false
mka_participant_1_secy_installed=false
mka_participant_1_live_peers=1
```

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
   │                               │  participant_B records SAK_B (standby)│
   │                               │                                       │
   │                               │  State: traffic flowing via SAK_A     │
```

### 6.2 Hitless Primary Key Rollover

```
Operator                    wpa_supplicant                          Peer
   │                               │                                  │
   │  Step 1: Ensure fallback      │                                  │
   │  key is already configured    │                                  │
   │  (live peers on both sides)   │                                  │
   │                               │  participant_A: principal        │
   │                               │  participant_B: standby, peers OK│
   │                               │                                  │
   │  Step 2: Delete primary key   │                                  │
   │  mka_del_key <primary_ckn>    │                                  │
   │──────────────────────────────>│                                  │
   │                               │  Delete participant_A            │
   │                               │  enforce_single_principal():     │
   │                               │    participant_B → principal     │
   │                               │    secy_installed = true          │
   │                               │  participant_B creates TxSC      │
   │                               │  participant_B distributes SAK_B │
   │                               │  SAK_B installed (AN=2)          │
   │                               │                                  │
   │                               │  Traffic continues via SAK_B     │
   │                               │  (was already in RxSA — zero gap)│
   │                               │                                  │
   │  Step 3: Add new primary key  │                                  │
   │  mka_add_key <new_cak> <ckn>  │                                  │
   │──────────────────────────────>│                                  │
   │                               │  Create participant_C (standby)  │
   │                               │  MKPDU exchange → peers established
   │                               │                                  │
   │  Step 4: Delete old fallback  │                                  │
   │  mka_del_key <fallback_ckn>   │                                  │
   │──────────────────────────────>│                                  │
   │                               │  Delete participant_B            │
   │                               │  participant_C → principal       │
   │                               │  Traffic now via SAK_C           │
```

### 6.3 Hitless Fallback Key Update

The fallback key can be rotated at any time while the primary key is active.
Use `mka_update_key` for an atomic replacement:

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
wpa_cli -i <iface> mka_del_key <compromised_ckn>
```

If this was the principal, the remaining participant takes over immediately. There may be a brief traffic disruption if the backup participant hasn't yet established live peers — this is by design (security > availability for compromised keys).

## 7 IEEE Spec Conformance

| Spec Reference | Clause | Status | Notes |
| -------------- | ------ | ------ | ----- |
| 802.1X-2020 §9.14 | ≥2 simultaneous participants per KaY | ✅ Conformant | `participant_list` holds multiple participants |
| 802.1X-2020 §12.1 | Principal actor selection | ✅ Conformant | `enforce_single_principal()` with priority + Dist-SAK recency |
| 802.1X-2020 §9.5 | MKA Life Time before SAK distribution | ✅ Conformant | `started_participating` timer check |
| 802.1X-2020 §9.9 | AN follows last in-use AN | ✅ Conformant | `ieee802_1x_kay_next_an()` scans all participants |
| 802.1X-2020 §9.10 | Only principal installs SAs | ✅ Conformant | `secy_installed` gates on all CP paths |
| 802.1X-2020 §11.1/§11.11 | MKPDUs via uncontrolled port | ✅ Conformant | L2 socket, not via MACsec datapath |
| 802.1AE-2018 §7.1.2/§7.1.3 | Multiple SAs per SC | ✅ Conformant | Shared RxSC, distinct ANs |
| 802.1AE-2018 §10.3 | SC internal representation | ✅ Conformant | Sharing is implementation detail |

## 8 Files Changed

All changes are within the `sonic-wpa-supplicant` repository:

| File | Lines Changed | Description |
| ---- | ------------- | ----------- |
| `src/pae/ieee802_1x_kay.c` | +520/−120 | Core: shared SC, principal selection, AN allocation, SecY gating, timing, helpers |
| `src/pae/ieee802_1x_kay_i.h` | +10 | `secy_installed` flag, `started_participating` timestamp |
| `wpa_supplicant/config.c` | +76 | Parse/write `mka_cak2`, `mka_ckn2` |
| `wpa_supplicant/config_ssid.h` | +17 | Backup key fields in `struct wpa_ssid` |
| `wpa_supplicant/ctrl_iface.c` | +210 | `MKA_ADD_KEY`, `MKA_DEL_KEY`, `MKA_UPDATE_KEY` control interface handlers |
| `wpa_supplicant/wpa_cli.c` | +70 | CLI commands (`mka_add_key`, `mka_del_key`, `mka_update_key`) and `network_fields` entries |
| `wpa_supplicant/wpas_kay.c` | +31/−1 | Create backup participant in `ieee802_1x_create_preshared_mka()` |

## 9 Testing

### 9.1 Unit Tests

| Test Case | Description |
| --------- | ----------- |
| Single-key backward compat | Configure only `mka_cak`/`mka_ckn`; verify identical behavior to unmodified code |
| Dual-key startup | Configure both primary and fallback; verify two participants created, only one principal |
| Runtime key add | `mka_add_key` creates standby participant; verify MKPDU exchange |
| Runtime key delete (standby) | `mka_del_key` on standby; verify principal unaffected |
| Runtime key delete (principal) | `mka_del_key` on principal; verify SecY transfer to standby |
| Runtime key update (standby) | `mka_update_key` replaces standby; verify principal unaffected, new standby starts MKPDU |
| Runtime key update (invalid) | `mka_update_key` with non-existent `old_ckn`; verify error returned, no state change |
| AN allocation | With two participants holding different ANs, verify `ieee802_1x_kay_next_an()` picks correctly |
| MKA Life Time | New participant cannot distribute SAK before `MKA_LIFE_TIME` elapses |
| Shared RxSC | Verify second participant reuses first's RxSC rather than creating duplicate |
| Principal selection priority | With two eligible participants, verify highest-priority Key Server wins |
| max\_sa\_per\_sc < 4 rejected | Attempt `mka_add_key` on hardware reporting 2 ANs; verify error returned, no standby created |

### 9.2 VS (Virtual Switch) Tests

End-to-end tests using veth pairs or KVM-based virtual switches:

| Test Case | Description |
| --------- | ----------- |
| Hitless primary rollover | Ping continuously; rotate primary key; verify zero packet loss |
| Hitless fallback update | Ping continuously; replace fallback key via `mka_update_key`; verify zero packet loss |
| Full key rotation cycle | Execute T0→T5 lifecycle (§6.3); verify both keys rotated with zero traffic loss |
| Simultaneous rollover | Both sides delete primary simultaneously; verify recovery via fallback |
| Key revocation | Delete principal without fallback established; verify graceful degradation |

## 10 Limitations and Future Work

1. **MACsec Mgr integration**: MACsec Mgr needs to be updated to map `fallback_cak`/`fallback_ckn` from Config DB to the `mka_cak2`/`mka_ckn2` fields (or use `mka_add_key`/`mka_del_key`/`mka_update_key` at runtime). This is a straightforward change but out of scope for this wpa\_supplicant HLD.

2. **Maximum participants**: The design supports exactly 2 concurrent participants (primary + fallback). Extending to N participants is architecturally possible but adds AN exhaustion risk (only 4 ANs available) and is not required by any known use case.

3. **Full link build**: The wpa\_supplicant full link currently fails due to pre-existing `-Werror` issues with OpenSSL 3.0 deprecation warnings in unrelated `dpp_*.c` files. Individual `.o` compilation of all modified files succeeds cleanly.

4. **EAP/802.1X mode**: This design targets PSK (pre-shared key) mode only. EAP-based MACsec has its own key hierarchy and does not use this rollover mechanism.

5. **show macsec CLI**: The existing `show macsec` CLI in sonic-utilities may need updates to display per-participant status. This is out of scope for this document.
