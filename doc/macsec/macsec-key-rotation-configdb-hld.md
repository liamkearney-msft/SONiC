<!-- omit in toc -->
# MACsec Key Rotation via Config DB — High Level Design Document

***Revision***

|  Rev  |    Date    |    Author    | Change Description |
| :---: | :--------: | :----------: | ------------------ |
|  0.1  | 2026-06-18 | Liam Kearney | Initial version    |

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
   - A primary key change is rejected unless an established fallback session exists to carry traffic during the rotation.
   - A fallback key change is rejected unless the primary is the active principal.
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

Hitless rotation reuses the shared-SC warm-standby mechanism, which requires the ASIC/PHY to support `max_sa_per_sc >= 4` (all four Association Numbers per Secure Channel). The rationale is given in [PSK/CAK Rollover HLD §1.2](./macsec-psk-rollover-hld.md): two concurrent participants each need SAK-rotation headroom. On hardware reporting fewer than 4 ANs, wpa\_supplicant rejects the standby participant and MACsec Mgr falls back to the brief-outage path in §4.3.

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

1. Snapshot the existing profile before applying the update (`old = m_profiles[name]`).
2. Apply `profile.update(attrs)` to obtain the new values.
3. If the profile is bound to one or more ports, compute:
   - `primary_changed = (old.primary_ckn != new.primary_ckn) || (old.primary_cak != new.primary_cak)`
   - `fallback_changed = (old.fallback_ckn != new.fallback_ckn) || (old.fallback_cak != new.fallback_cak)`
4. For each affected port and changed pair, issue the matching `wpa_cli` command.
5. Non-key field changes on an in-use profile retain existing behaviour (logged, not applied).

The placeholder is replaced with:

```cpp
if (profile_in_use) {
    if (primary_changed) {
        if (!fallbackEstablished(port))            // no carrier for the gap
            return task_failed;
        rotateKey(port, old.primary_ckn, new.primary_cak, new.primary_ckn);
    }
    if (fallback_changed) {
        if (!primaryIsPrincipal(port))             // fallback may be carrying traffic
            return task_failed;
        if (new.fallback_ckn.empty())
            deleteKey(port, old.fallback_ckn);                  // fallback removed
        else if (old.fallback_ckn.empty())
            addKey(port, new.fallback_cak, new.fallback_ckn);   // fallback added
        else
            rotateKey(port, old.fallback_ckn, new.fallback_cak, new.fallback_ckn);
    }
}
```

`fallbackEstablished()` and `primaryIsPrincipal()` evaluate the precondition in §1.1 item 3 against the live MKA participant state reported by wpa\_supplicant `status` over the port socket. If the precondition is not met, the update returns `task_failed`, no `wpa_cli` command is issued, and the live session is left untouched. This is a backstop; the CLI performs the same check before writing Config DB (§5).

The helpers wrap the control-interface commands defined in the companion HLD, using the per-port socket already held in `MKASession::sock`:

```bash
# rotateKey(): atomic replacement of one key
wpa_cli -g {{sock}} IFNAME={{port}} mka_update_key old_ckn={{old_ckn}} cak={{new_cak}} ckn={{new_ckn}}

# addKey(): introduce a fallback where there was none
wpa_cli -g {{sock}} IFNAME={{port}} mka_add_key {{cak}} {{ckn}}

# deleteKey(): remove a fallback
wpa_cli -g {{sock}} IFNAME={{port}} mka_del_key {{ckn}}
```

Each command's reply is checked. A non-`OK` reply returns `task_need_retry`, so the orchagent retries the entry on the next sync cycle.

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
wpa_supplicant: delete participant(CKN_A)
                    -> principal election promotes CKN_F (fallback)
                    -> datapath rides on the already-installed CKN_F SAK, no loss
                create participant(CKN_B), establish with peer
                    -> CKN_B installs its SAK on a free AN
                    -> principal election returns to CKN_B
        |
        v
Traffic protected by CKN_B (new primary). Fallback CKN_F returns to standby.
```

The update is applied to both peers. The fallback carries traffic during the window in which the new primary establishes (a few seconds for the MKA handshake). Without an established fallback there is no session to cover that window, which is why the precondition is enforced.

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

- Missing backup session: a primary key change is rejected when no established fallback session exists, and a fallback key change is rejected when the primary is not the active principal. The precondition is checked before the rotation is issued (§5, §3.2), so a rejected change does not perturb the live session.
- Peer not yet updated: the new participant never reaches live-peer state and is not elected principal. The old key keeps the link up, and the rotation completes once the peer is updated.
- `max_sa_per_sc < 4` hardware: wpa\_supplicant rejects the standby participant. MACsec Mgr detects the error reply and logs a warning. A brief-outage rotation (delete old key, add new key) is then required and is gated behind an explicit operator decision rather than performed by default.
- `wpa_cli` non-`OK` or socket error: `rotateKey()` returns `task_need_retry`; the orchagent retries on the next cycle. Config DB remains the source of truth, so a missed update is reapplied.
- Invalid new key (bad hex or length): rejected at the CLI layer (§5) before reaching Config DB, using the same checks as `config macsec profile add`.

## 5 CLI

A `update` sub-command is added to the `config macsec profile` group in `sonic-utilities` (`config/plugins/macsec.py`). It overwrites the key fields of an existing profile in place, unlike `add`, which refuses to overwrite, and `del`, which refuses while in use.

```
config macsec profile update <profile_name>
        [--primary_cak <cak>] [--primary_ckn <ckn>]
        [--fallback_cak <cak>] [--fallback_ckn <ckn>]
```

Behaviour:

- The profile must already exist, otherwise the command fails.
- `--primary_cak` and `--primary_ckn` must be supplied together; the same applies to the fallback pair.
- CAK length is validated against the profile's `cipher_suite` (66 hex characters for 128-bit, 130 for 256-bit), and CAK and CKN are validated as hex strings, matching `profile add`.
- Only the supplied fields are modified; the existing row is read, updated, and written back.
- The rotation precondition (§1.1 item 3) is checked against the live MKA participant state (from STATE_DB, as surfaced by `show macsec`) before the row is written: a primary key change requires an established fallback session, and a fallback key change requires the primary to be the active principal. If the precondition is not met the command fails and Config DB is not modified.
- Writing the row triggers the MACsec Mgr flow in §3.2, which re-checks the precondition as a backstop.

Example:

```bash
config macsec profile update Profile1 \
    --primary_cak 0123...new... --primary_ckn ABCD...new...
```

The same command is run on both peers. `show macsec` is extended to report per-participant state already exported by wpa\_supplicant `status` (companion HLD §5.3):

```
MACsec port(Ethernet0)
    profile: Profile1
    ...
    MKA participants:
        CKN_B  principal=true   secy_installed=true   live_peers=1
        CKN_C  principal=false  secy_installed=false  live_peers=1
```

## 6 Warm Reboot / Config Reload

- Config reload: the `MACSEC_PROFILE` row holds the current keys, because rotation overwrites it in place. A reload reapplies the latest keys with no special handling. There is no separate rotation state to persist.
- Warm reboot: unchanged from the base design. wpa\_supplicant re-reads the profile and establishes the session on the current keys. A rotation should be completed and verified before a warm reboot rather than initiated across the boundary.

## 7 Files Changed

| Repo | File | Change |
| ---- | ---- | ------ |
| sonic-swss | `cfgmgr/macsecmgr.cpp` | Implement the `Hot update` branch: key diffing and `rotateKey()` / `addKey()` / `deleteKey()` helpers issuing `mka_update_key` / `mka_add_key` / `mka_del_key`; snapshot the previous profile in `loadProfile()`. |
| sonic-swss | `cfgmgr/macsecmgr.h` | Declarations for the new helpers. |
| sonic-utilities | `config/plugins/macsec.py` | `config macsec profile update` command with in-place key validation and overwrite. |
| sonic-utilities | `show/plugins/macsec.py` | Report per-participant MKA state in `show macsec`. |
| sonic-wpa-supplicant | (none) | Provides the `mka_*_key` commands; see companion HLD. |

## 8 Testing

| Test | Description |
| ---- | ----------- |
| Primary rotation | Overwrite `primary_cak`/`primary_ckn` on a live VS link on both peers; assert no ping loss and that `show macsec` reports the new CKN as principal. |
| Fallback rotation | Overwrite `fallback_cak`/`fallback_ckn`; assert principal and SecY unchanged and the standby CKN updated. |
| Add/remove fallback | Add fallback fields where none existed, then clear them; verify participant count. |
| Idempotent write | Re-write identical key values; assert no `mka_*` command is issued. |
| One-sided rotation | Update one peer only; assert the link stays up on the old key and converges once the second peer is updated. |
| Reject primary without fallback | Update `primary_*` on a profile with no established fallback; assert the command fails and Config DB is unchanged. |
| Reject fallback when primary not principal | Bring the primary down so the fallback is principal, then update `fallback_*`; assert the change is rejected. |
| CLI validation | `config macsec profile update` with bad hex, wrong CAK length, or nonexistent profile is rejected. |
| Retry on socket error | wpa\_supplicant unavailable; assert `task_need_retry` and eventual convergence. |
| `max_sa_per_sc < 4` | VS reporting fewer than 4 ANs; assert the rejection is logged and no principal is lost. |

VS tests are added to the MACsec test plan in `sonic-mgmt`. CLI unit tests go in `dockers/docker-macsec/cli-plugin-tests/test_config_macsec.py`.

## 9 Limitations

1. Rotating the CAK while keeping the same CKN is not supported (duplicate-CKN rejection in wpa\_supplicant). A fresh CKN is required per rotation.
2. Hardware reporting fewer than 4 ANs (`max_sa_per_sc < 4`) cannot rotate hitlessly; a brief-outage path is available but not default.
3. Rotation is hitless only once both peers carry the new key. Coordination of the two-sided update is out of scope.
4. Changing `cipher_suite`, `priority`, `policy`, and other non-key fields on a live profile remains unsupported; only CAK/CKN are hot-updatable.
5. The key diff relies on MACsec Mgr holding the last-applied keys. After a `macsecmgrd` restart the baseline is rebuilt from Config DB, which already reflects current keys, so no spurious rotation occurs.
6. The CLI precondition check (§5) depends on per-participant MKA state (principal, established) being available in STATE_DB. This requires the SONiC MACsec plugin / MACsec Mgr to publish that state, derived from wpa\_supplicant `status` (companion HLD §5.3). Where it is not yet available, the check is enforced only by the MACsec Mgr backstop (§3.2).
