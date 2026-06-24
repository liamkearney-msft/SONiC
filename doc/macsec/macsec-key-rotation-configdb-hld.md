<!-- omit in toc -->
# MACsec Key Rotation via Config DB — High Level Design Document

***Revision***

|  Rev  |    Date    |    Author    | Change Description |
| :---: | :--------: | :----------: | ------------------ |
|  0.1  | 2026-06-18 | Liam Kearney | Initial version    |
|  0.2  | 2026-06-19 | Liam Kearney | Aligned with implementation |
|  0.3  | 2026-06-22 | Liam Kearney | Warm dual-SAK & non-simultaneous rollover (companion HLD) |
|  0.4  | 2026-06-24 | Liam Kearney | CLI config-level rejects: a primary rotation with no fallback configured, and updating both keys at once; precondition split into config-level (CLI) and runtime (MACsec Mgr) |

<!-- omit in toc -->
## Table of Contents

- [About this Manual](#about-this-manual)
- [Scope](#scope)
- [Definitions / Abbreviations](#definitions--abbreviations)
- [1 Requirements Overview](#1-requirements-overview)
  - [1.1 Functional Requirements](#11-functional-requirements)
  - [1.2 Non-Functional Requirements](#12-non-functional-requirements)
  - [1.3 Hardware Requirements](#13-hardware-requirements)
- [2 Architecture Design](#2-architecture-design)
  - [2.1 Problem Statement](#21-problem-statement)
  - [2.2 Approach](#22-approach)
- [3 Modules Design](#3-modules-design)
  - [3.1 Config DB](#31-config-db)
  - [3.2 MACsec Mgr](#32-macsec-mgr)
  - [3.3 wpa\_supplicant](#33-wpa_supplicant)
- [4 Flows](#4-flows)
  - [4.1 Primary Key Rotation](#41-primary-key-rotation)
  - [4.2 Fallback Key Rotation](#42-fallback-key-rotation)
  - [4.3 Error Handling](#43-error-handling)
- [5 CLI](#5-cli)
- [6 Warm Reboot / Config Reload](#6-warm-reboot--config-reload)
- [7 Files Changed](#7-files-changed)
- [8 Testing](#8-testing)
- [9 Limitations](#9-limitations)

## About this Manual

This document extends the [MACsec SONiC HLD](https://github.com/sonic-net/SONiC/blob/master/doc/macsec/MACsec_hld.md). It describes how the pre-shared keys (CAK/CKN) of a live MACsec session are rotated by overwriting the `primary_cak`/`primary_ckn` or `fallback_cak`/`fallback_ckn` fields of an in-use `MACSEC_PROFILE` row in Config DB, without taking the link down.

It implements Phase III of the MACsec HLD functional requirements ("Primary and Fallback secure Connectivity Association Key can be supported simultaneously") and provides the content for section `3.4.1.1 Primary/Fallback decision`, which is currently marked `TODO`.

## Scope

This document covers the SONiC orchestration layer:

- `MACSEC_PROFILE` Config DB semantics.
- MACsec Mgr (`macsecmgrd`) key-change detection and translation to `wpa_cli` commands.
- The `config macsec profile` CLI in `sonic-utilities`.

It does not re-describe the wpa\_supplicant / KaY internals that make the rotation hitless. Those are specified in the companion [MACsec PSK/CAK Rollover HLD](./macsec-psk-rollover-hld.md), which defines the shared-SC warm-standby model, principal-actor selection, AN allocation, and the `mka_add_key` / `mka_del_key` / `mka_update_key` control-interface commands. This document treats those commands as a fixed interface.

## Definitions / Abbreviations

| Abbreviation | Description                              |
| ------------ | ---------------------------------------- |
| CAK          | Connectivity Association Key             |
| CKN          | CAK Name                                 |
| CA           | Connectivity Association                 |
| KaY          | MACsec Key Agreement Entity              |
| MKA          | MACsec Key Agreement Protocol            |
| Participant  | One KaY actor bound to a single CAK/CKN  |
| SAK          | Secure Association Key                    |
| SecY         | MACsec Security Entity (datapath)        |

## 1 Requirements Overview

### 1.1 Functional Requirements

1. The primary PSK of an in-use MACsec profile is rotated by overwriting `primary_cak`/`primary_ckn` in `MACSEC_PROFILE`. The rotation requires an already-established fallback session and proceeds as:
   1. The old primary participant is removed. The fallback, a live warm-standby participant with its SAK already installed, takes over the datapath without data loss.
   2. A participant for the new primary key is created and establishes with the peer.
   3. The datapath returns to the new primary once it is established. The fallback returns to standby.
2. The fallback PSK is rotated by overwriting `fallback_cak`/`fallback_ckn`. The fallback is not carrying traffic while the primary is principal, so its participant is dropped and re-established on the new key in place.
3. A key change that would leave the port without a protecting session is rejected:
   - A primary key change is rejected unless a fallback exists to carry traffic during the rotation — that one is *configured* is checked at the CLI (§5); that it is *established* (a live peer) is checked by MACsec Mgr (§3.2).
   - A fallback key change is rejected unless the primary is the active principal (MACsec Mgr, §3.2).
4. Rotation does not interrupt data-plane traffic on the affected ports while both peers are reachable and have been configured with the new key.
5. Rotation is driven from Config DB only. No `config reload`, port flap, or `config macsec port del/add` is required.
6. When a profile is bound to multiple ports, the rotation is applied to every port using that profile.
7. Profile add/remove and port bind/unbind behaviour is unchanged.

### 1.2 Non-Functional Requirements

1. The change is confined to MACsec Mgr and the `config macsec` CLI plugin. No SAI, MACsec Orch, App DB, or State DB schema change.
2. Re-writing identical key values produces no rotation; keys are diffed before any action.
3. Profiles that are never updated behave as in the base design.
4. A port is driven by exactly one principal participant at any instant. A partially applied rotation does not leave a port with two principals or none.

### 1.3 Hardware Requirements

Hitless rotation reuses the shared-SC warm-standby mechanism, which requires the ASIC/PHY to support `max_sa_per_sc >= 4` (all four Association Numbers per Secure Channel). The rationale is given in [PSK/CAK Rollover HLD §1.2](./macsec-psk-rollover-hld.md): two concurrent participants each need SAK-rotation headroom. On hardware reporting fewer than 4 ANs, wpa\_supplicant rejects the new standby participant, so hitless rotation is not available on those platforms (see §4.3).

## 2 Architecture Design

### 2.1 Problem Statement

In the current implementation, a `MACSEC_PROFILE` row is effectively immutable once a port uses it:

- `config macsec profile` supports only `add` and `del`. `add` refuses to overwrite an existing profile; `del` refuses while any port references it.
- `MACsecMgr::loadProfile()` receives the `SET` notification when a profile row changes and contains a placeholder that performs no action:

  ```cpp
  // If the profile has been used
  if (profile.second) {
      for (auto & port : m_macsec_ports) {
          if (port.second.profile_name == profile_name) {
              // Hot update
              SWSS_LOG_DEBUG("Hot update");
          }
      }
  }
  ```

A key change in Config DB is therefore parsed but never pushed to wpa\_supplicant. Changing a live CAK today requires removing MACsec from the port, deleting and re-adding the profile, and re-binding, which drops the link and forces re-authentication.

The wpa\_supplicant layer already supports hitless multi-key rotation (companion HLD). The missing piece is the orchestration that detects the Config DB key change and issues the corresponding `wpa_cli` sequence.

### 2.2 Approach

Implement the `Hot update` branch in MACsec Mgr as a key-diff driver:

1. MACsec Mgr caches the previously applied `MACsecProfile` in `m_profiles`.
2. On a `SET` to an in-use profile, it compares the old and new `(primary_cak, primary_ckn)` and `(fallback_cak, fallback_ckn)` pairs.
3. For each changed pair, for each port bound to the profile, it issues one `wpa_cli mka_update_key` (or `mka_add_key` / `mka_del_key`) to that port's wpa\_supplicant instance.
4. wpa\_supplicant performs the shared-SC warm-standby swap. The SecY is not torn down.

```
        config macsec profile update <profile> --primary_cak <new> --primary_ckn <new>
                                   |
                                   v
                   Config DB: MACSEC_PROFILE|<profile>  (row overwritten in place)
                                   |  SET notification
                                   v
        +----------------------------------------------------------+
        |  MACsec Mgr (macsecmgrd)                                  |
        |    loadProfile(): diff old vs new keys                    |
        |    for each port using <profile>:                        |
        |        wpa_cli -g <sock> IFNAME=<port> \                  |
        |            mka_update_key old_ckn=<old> cak=<new> ckn=<new>|
        +----------------------------------------------------------+
                                   |
                                   v
        +----------------------------------------------------------+
        |  wpa_supplicant / KaY  (companion HLD)                   |
        |    create standby participant for new key                |
        |    principal election -> SecY swap                        |
        |    delete old participant (no datapath teardown)         |
        +----------------------------------------------------------+
```

## 3 Modules Design

### 3.1 Config DB

The `MACSEC_PROFILE` schema is unchanged from MACsec HLD §3.1.1:

```rfc5234
MACSEC_PROFILE|{{profile}}
    "primary_cak":{{primary_cak}}
    "primary_ckn":{{primary_ckn}}
    "fallback_cak":{{fallback_cak}} (OPTIONAL)
    "fallback_ckn":{{fallback_ckn}} (OPTIONAL)
    ... (other fields unchanged) ...
```

The semantics change is that the `*_cak` / `*_ckn` fields are mutable in place for a profile bound to ports. An in-place overwrite, previously parsed and ignored, now triggers a rotation. Other fields (`priority`, `cipher_suite`, `policy`, and so on) remain immutable while in use; changing them on a live profile is out of scope and continues to be logged without effect.

Field-to-participant mapping (from the companion HLD):

| Config DB Field | wpa\_supplicant participant |
| --------------- | --------------------------- |
| `primary_cak` / `primary_ckn`   | primary participant (`mka_cak` / `mka_ckn`)   |
| `fallback_cak` / `fallback_ckn` | fallback participant (`mka_cak2` / `mka_ckn2`) |

### 3.2 MACsec Mgr

`MACsecMgr::MACsecProfile` already stores `primary_cak`, `primary_ckn`, `fallback_cak`, and `fallback_ckn`. `loadProfile()` is extended as follows:

1. Build a candidate profile from the incoming attributes without committing it, so a rejected update leaves both `m_profiles` and the running wpa\_supplicant configuration unchanged.
2. If the profile did not previously exist, or is not bound to any port, store it as-is (initial load or non-key update; non-key fields are not hot-applied).
3. Otherwise snapshot the previous profile (`old = m_profiles[name]`) and compute:
   - `primary_changed = (old.primary_ckn != new.primary_ckn) || (old.primary_cak != new.primary_cak)`
   - `fallback_changed = (old.fallback_ckn != new.fallback_ckn) || (old.fallback_cak != new.fallback_cak)`
4. Rotating both the primary and fallback in a single operation is rejected: there would be no stable session to carry traffic across the second rotation, so the operator must rotate one key at a time.
5. For the single changed pair, apply the matching `wpa_cli` command to every port using the profile. `m_profiles` is committed only after all ports succeed, so a precondition rejection or a transient failure preserves the diff for a later retry.

The placeholder is replaced with the following logic (`loadProfile()` decides, `hotUpdateProfile()` applies per port):

```cpp
// loadProfile(): at most one key pair changes per operation
if (primary_changed && fallback_changed)
    return task_failed;                            // rotate one key at a time

// hotUpdateProfile(port): evaluated against `wpa_cli ... status`
if (primary_changed) {
    if (new.primary_ckn is already a participant)  // already rotated (idempotent)
        skip;
    else if (fallback CKN has no live peer)         // no carrier for the gap
        return task_failed;
    else
        mka_update_key(old.primary_ckn, new.primary_cak, new.primary_ckn);
}
if (fallback_changed) {
    if (new.fallback_ckn is empty)
        mka_del_key(old.fallback_ckn);              // fallback removed
    else if (new.fallback_ckn is already a participant)
        skip;                                       // already updated (idempotent)
    else if (primary CKN has no live peer)          // primary not the active session
        return task_failed;
    else if (old.fallback_ckn is empty)
        mka_add_key(new.fallback_cak, new.fallback_ckn);   // fallback added
    else
        mka_update_key(old.fallback_ckn, new.fallback_cak, new.fallback_ckn);
}
```

The preconditions in §1.1 item 3 are evaluated against the per-participant MKA state in the `wpa_cli ... status` reply for the port. The KaY status lists each participant's `ckn` and `live_peers` count; MACsec Mgr treats a participant with at least one live peer as established. A primary rotation requires the fallback CKN to have a live peer, and a fallback rotation requires the primary CKN to have a live peer. If the precondition is not met the update returns `task_failed`, no `wpa_cli` command is issued, and the live session is left untouched. MACsec Mgr is the sole enforcement point; the CLI performs field validation only (§5).

The helpers wrap the control-interface commands defined in the companion HLD, using the per-port socket already held in `MKASession::sock`. The CAK is passed decoded (plain hex), and the commands use `key=value` arguments:

```bash
# replace one key (delete the old participant, then create the new one)
wpa_cli -g {{sock}} IFNAME={{port}} mka_update_key old_ckn={{old_ckn}} cak={{new_cak}} ckn={{new_ckn}}

# introduce a fallback where there was none
wpa_cli -g {{sock}} IFNAME={{port}} mka_add_key cak={{cak}} ckn={{ckn}}

# remove a fallback
wpa_cli -g {{sock}} IFNAME={{port}} mka_del_key ckn={{ckn}}
```

`mka_update_key` is a delete-then-create, not an atomic swap; the old participant is removed first so its Association Numbers are freed before the replacement claims one. Each command's reply is checked, and a non-`OK` reply returns `task_need_retry`, so the entry is retried on the next sync cycle. Already-applied rotations are detected from the status snapshot and skipped, making the retry idempotent.

The new CKN must differ from the CKN it replaces. wpa\_supplicant rejects duplicate CKNs, and `mka_update_key` is a delete-then-create. Rotating the CAK while keeping the same CKN is therefore not supported; a new CKN must be supplied alongside a new CAK.

This document also changes the `CAK` and `CKN` rows of the MACsec HLD §3.4.1.2 parameter table from `Hot Update = N` to `Hot Update = Y`:

| Parameter | Hot Update (old) | Hot Update (new) | Mechanism |
| :-------: | :--------------: | :--------------: | --------- |
| `CAK` (primary) | N | Y | `mka_update_key` |
| `CKN` (primary) | N | Y | `mka_update_key` |
| `fallback_cak`  | — | Y | `mka_update_key` / `mka_add_key` / `mka_del_key` |
| `fallback_ckn`  | — | Y | `mka_update_key` / `mka_add_key` / `mka_del_key` |

### 3.3 wpa\_supplicant

No change in this HLD. The control-interface commands (`mka_add_key`, `mka_del_key`, `mka_update_key`), the shared-SC warm-standby model, principal-actor selection, and the `max_sa_per_sc >= 4` guard are specified and implemented in the companion [PSK/CAK Rollover HLD](./macsec-psk-rollover-hld.md). MACsec Mgr is a client of those commands.

## 4 Flows

### 4.1 Primary Key Rotation

Profile `P` is bound to port `Ethernet0`. The primary `CKN_A` is principal and an established fallback `CKN_F` is a live warm standby. The precondition (fallback established) is required; if it is not met the change is rejected (§4.3, §5).

```
Operator (each peer):  config macsec profile update P --primary_cak CAK_B --primary_ckn CKN_B
        |
        v
Config DB:  MACSEC_PROFILE|P  primary_cak=CAK_B  primary_ckn=CKN_B   (overwritten)
        |  SET notification
        v
MACsec Mgr:  primary_changed = true (CKN_A -> CKN_B), fallback CKN_F established
             for Ethernet0:
                 wpa_cli IFNAME=Ethernet0 mka_update_key old_ckn=CKN_A cak=CAK_B ckn=CKN_B
        |
        v
wpa_supplicant: (warm dual-SAK behaviour — see companion HLD §2.2, §3.5)
                move transmit OFF the old primary CKN_A onto the
                already-installed fallback SAK (CKN_F) — peer already
                receives it, so no loss; drain CKN_A's receive SA
                create participant(CKN_B); once both peers share CKN_B it
                distributes its SAK and installs receive SAs (warm)
                transmit returns from fallback to the new primary CKN_B
        |
        v
Traffic protected by CKN_B (new primary). Fallback CKN_F returns to standby.
```

The update is applied to both peers, in general **at different times**. Because the fallback SAK is already installed for receive on both ends, each peer can switch its transmit onto the fallback independently while the new primary establishes; traffic rides the fallback throughout the window. This non-simultaneous behaviour, the draining of the old primary, and the return to the primary slot are specified in the companion [PSK/CAK Rollover HLD](./macsec-psk-rollover-hld.md) (§2.2, §3.5, §6.2). The precondition (an established, warm fallback) is what makes this window lossless, which is why it is enforced.

### 4.2 Fallback Key Rotation

The changed pair is the fallback. The precondition is that the primary is the active principal, so the fallback is a non-principal standby and replacing it does not touch the principal or the SecY. If the primary is not principal (for example it is down and the fallback is currently carrying traffic), the change is rejected (§4.3, §5).

```
config macsec profile update P --fallback_cak CAK_C --fallback_ckn CKN_C
    -> MACsec Mgr: fallback_changed = true (CKN_old -> CKN_C)
    -> wpa_cli IFNAME=EthernetX mka_update_key old_ckn=CKN_old cak=CAK_C ckn=CKN_C
    -> wpa_supplicant swaps the standby participant; principal unaffected.
```

Adding a fallback to a profile that had none issues `mka_add_key`. Clearing the fallback fields issues `mka_del_key`.

### 4.3 Error Handling

- Both keys changed at once: rejected at the CLI before reaching Config DB (§5), with MACsec Mgr rejecting it as a backstop; the operator must rotate the primary and fallback keys in separate operations.
- Missing backup session: a primary key change with **no fallback configured** is rejected at the CLI before it reaches Config DB (§5). A primary change where the configured fallback is **not yet established** (no live peer), and a fallback change while the primary is not the active principal, are rejected by MACsec Mgr before the rotation is issued (§3.2), so a rejected change does not perturb the live session.
- Peer not yet updated: the new participant never reaches live-peer state and is not elected principal. The old key keeps the link up, and the rotation completes once the peer is updated.
- `max_sa_per_sc < 4` hardware: wpa\_supplicant rejects the new standby participant, so the `wpa_cli` command fails and the entry is retried. Hitless rotation is not possible on such hardware; the change cannot be applied without a brief outage.
- `wpa_cli` non-`OK` or socket error: `hotUpdateProfile()` returns `task_need_retry`; the orchagent retries on the next cycle. Config DB remains the source of truth, so a missed update is reapplied.
- Invalid new key (bad hex or length): rejected at the CLI layer (§5) before reaching Config DB, using the same checks as `config macsec profile add`.

## 5 CLI

A `update` sub-command is added to the `config macsec profile` group (`dockers/docker-macsec/cli/config/plugins/macsec.py` in sonic-buildimage). It overwrites the key fields of an existing profile in place, unlike `add`, which refuses to overwrite, and `del`, which refuses while in use.

```
config macsec profile update <profile_name>
        [--primary_cak <cak>] [--primary_ckn <ckn>]
        [--fallback_cak <cak>] [--fallback_ckn <ckn>]
```

Behaviour:

- The profile must already exist, otherwise the command fails.
- `--primary_cak` and `--primary_ckn` must be supplied together; the same applies to the fallback pair.
- The primary and fallback keys cannot be updated in the same command — they must be rotated one at a time, so a stable session carries traffic across each rotation. Supplying both pairs is rejected at the CLI (MACsec Mgr rejects it as a backstop, §3.2).
- CAK length is validated against the profile's `cipher_suite` (66 hex characters for 128-bit, 130 for 256-bit), and CAK and CKN are validated as hex strings, matching `profile add`.
- Only the supplied fields are modified; the existing row is read, updated, and written back.
- The CAK and CKN are validated together (existence, pairing, hex, and CAK length against the profile's `cipher_suite`); shared validation is factored into a `validate_cak` helper used by both `add` and `update`.
- The CLI enforces the **configuration-level** half of the rotation precondition (§1.1 item 3): a primary rotation is rejected when the profile has no fallback key configured, because a fallback is required to carry traffic during the swap. This needs only the CONFIG_DB profile row — no MKA state — so it fails fast at the command with a clear message and Config DB is left unchanged. The complementary **runtime** check — that the configured fallback is actually *established* (has a live peer), and that the primary is the active principal for a fallback rotation — depends on live MKA state the CLI cannot see and remains enforced authoritatively by MACsec Mgr (§3.2). Surfacing that runtime state to the CLI/`show` is future work (see §9).
- Writing the row triggers the MACsec Mgr flow in §3.2, which applies or rejects the rotation.

Example:

```bash
config macsec profile update Profile1 \
    --primary_cak 0123...new... --primary_ckn ABCD...new...
```

The same command is run on both peers. The rotation can be verified per port with `wpa_cli -g {{sock}} IFNAME={{port}} status`, which lists each MKA participant's `ckn`, `live_peers`, `is_key_server`, and `is_elected`. Surfacing this per-participant state through `show macsec` is future work (see §7, §9).

## 6 Warm Reboot / Config Reload

- Config reload: the `MACSEC_PROFILE` row holds the current keys, because rotation overwrites it in place. A reload reapplies the latest keys with no special handling. There is no separate rotation state to persist.
- Warm reboot: unchanged from the base design. wpa\_supplicant re-reads the profile and establishes the session on the current keys. A rotation should be completed and verified before a warm reboot rather than initiated across the boundary.

## 7 Files Changed

| Repo | File | Change |
| ---- | ---- | ------ |
| sonic-swss | `cfgmgr/macsecmgr.cpp` | Implement the `Hot update` branch: key diffing in `loadProfile()`, the `hotUpdateProfile()` per-port apply with precondition checks, and `mka_rotate_key` / `mka_add_key` / `mka_del_key` helpers plus a `wpa_cli ... status` participant parser. |
| sonic-swss | `cfgmgr/macsecmgr.h` | Declaration for `hotUpdateProfile()`. |
| sonic-buildimage | `dockers/docker-macsec/cli/config/plugins/macsec.py` | `config macsec profile update` command with in-place key validation and overwrite; shared `validate_cak` helper; config-level rejects (a primary rotation with no fallback configured, and updating both keys at once). |
| sonic-buildimage | `dockers/docker-macsec/cli-plugin-tests/test_config_macsec.py` | Unit tests for `config macsec profile update`. |
| sonic-utilities | `show/plugins/macsec.py` | (Future) Surface per-participant MKA state in `show macsec`. Not part of this change. |
| sonic-wpa-supplicant | (none) | Provides the `mka_*_key` commands; see companion HLD. |

## 8 Testing

| Test | Description |
| ---- | ----------- |
| Primary rotation | Overwrite `primary_cak`/`primary_ckn` on a live VS link on both peers; assert no ping loss and that `wpa_cli ... status` lists the new primary CKN with a live peer. |
| Fallback rotation | Overwrite `fallback_cak`/`fallback_ckn`; assert no ping loss, the primary CKN is unchanged, and `status` lists the new fallback CKN. |
| Add/remove fallback | Add fallback fields where none existed, then clear them; verify participant count. |
| Idempotent write | Re-write identical key values; assert no `mka_*` command is issued. |
| One-sided rotation | Update one peer only; assert the link stays up on the old key and converges once the second peer is updated. |
| Reject primary without fallback configured (CLI) | Update `primary_*` on a profile that has no fallback configured; assert the CLI rejects it and Config DB is unchanged. |
| Reject primary without fallback established (MACsec Mgr) | Configure a fallback but keep it down (no live peer); update `primary_*`; assert MACsec Mgr rejects it and the live session is untouched. |
| Reject fallback when primary not principal | Bring the primary down so the fallback is principal, then update `fallback_*`; assert the change is rejected. |
| Reject both keys at once | Update `primary_*` and `fallback_*` in one command; assert the CLI rejects it, Config DB is unchanged, and no `wpa_cli` command is issued. |
| CLI validation | `config macsec profile update` with bad hex, wrong CAK length, or nonexistent profile is rejected. |
| Retry on socket error | wpa\_supplicant unavailable; assert `task_need_retry` and eventual convergence. |
| `max_sa_per_sc < 4` | VS reporting fewer than 4 ANs; assert the rotation fails and the existing session is left intact (no outage from the attempt). |

VS tests are added to the MACsec test plan in `sonic-mgmt`. CLI unit tests are in `dockers/docker-macsec/cli-plugin-tests/test_config_macsec.py` (sonic-buildimage).

## 9 Limitations

1. Rotating the CAK while keeping the same CKN is not supported (duplicate-CKN rejection in wpa\_supplicant). A fresh CKN is required per rotation.
2. Hardware reporting fewer than 4 ANs (`max_sa_per_sc < 4`) cannot rotate hitlessly; the rotation fails. Changing the key on such hardware requires an explicit outage (for example, unbinding the profile, editing it, and rebinding) and is not automated.
3. Rotation is hitless only once both peers carry the new key. Coordination of the two-sided update is out of scope.
4. Changing `cipher_suite`, `priority`, `policy`, and other non-key fields on a live profile remains unsupported; only CAK/CKN are hot-updatable.
5. The key diff relies on MACsec Mgr holding the last-applied keys. After a `macsecmgrd` restart the baseline is rebuilt from Config DB, which already reflects current keys, so no spurious rotation occurs.
6. The rotation precondition (§1.1 item 3) is split by where the needed state lives. The CLI rejects a primary rotation when no fallback is *configured* (config-level, §5). Whether the configured fallback is actually *established* (a live peer), and whether the primary is the active principal for a fallback rotation, is runtime MKA state the CLI cannot see, so it is enforced only by MACsec Mgr (§3.2). Surfacing that runtime per-participant state to the CLI and `show macsec` (for example by publishing it to STATE_DB) is future work.
7. Rotating both the primary and fallback keys in a single `config macsec profile update` is rejected (at the CLI, with MACsec Mgr as a backstop); the two keys must be rotated in separate operations.
