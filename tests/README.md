# Tests

821 tests, no account, no network, no fixtures on disk except `golden/`.

```bash
python -m pytest tests/ -q                       # everything
UPDATE_GOLDEN=1 python -m pytest tests/test_golden.py   # rewrite the transcripts, then read the diff
```

## What these do and do not prove

- **They prove the assembly is intact.** Every layer reads back what the layer beside it
  writes, and the shapes that fail silently are pinned.
- **They do not prove Apple agrees.** Fixtures are built from this implementation's
  understanding of the format. A test that agrees with the client proves only that the two
  agree — the HMAC fixture in `test_pcs.py` built its digest the same wrong way as the
  client, and could never have caught the bug it was written around.
- **What a real account taught us is recorded as `[observed]`**, in a comment beside the
  fixture built to match it. Grep for it: eleven facts nothing offline could have found.

## Patterns, and which failure each one catches

| Pattern | Catches | Where |
| --- | --- | --- |
| **Round trip** — library writes, library reads | a layer disagreeing with itself | `seal_bottle`→`open_bottle`, `build_keyvault_message`→`parse_keyvault_message`, `sfies_encrypt`→`sfies_decrypt_archive` |
| **Independent writer** — a second implementation, written from the format | writer and reader being wrong the same way | `test_bottle.py`'s own `seal_bottle`, `test_location_reports.py`'s `encrypt_report`, `test_enrolment.py`'s manual unseal |
| **Opposite sections** — writer from one spec section, reader from another | two readings of one format that never meet | `build_inner_message` (§4.5.1) → `unwrap_inner_blob` (§6.5) |
| **Frozen transcript** — output committed as text | writer and reader drifting *together*, silently | `golden/`, see below |
| **Source inspection** — assert on the code, not its behaviour | a guarantee with no reachable call path | `ptkn` never sent; the GSA user agent staying transcribed |
| **Whole-account** — one synthetic account through every layer | a change that works per-hop and breaks the chain; an account *shape* nobody tested | `fake_account.py`, driven by `test_end_to_end.py` |

## Files

| File | Tests | Idea |
| --- | --- | --- |
| `test_keygen.py` | 100 | Key generation, 100 rounds. The oldest test here. |
| `test_pcs.py` | 95 | PCS decryption (Stage 5) and the DER reader under it. Hand-built DER, so a wrong parse is visible. |
| `test_beacons.py` | 79 | Decrypted records → accessories (Stage 6). Includes records → accessory → real rolling keys. |
| `test_items.py` | 59 | Keychain items (§6.8.1). Every failure here is silent: entry order, `wrappedkey` meaning two things, `encver` deciding how many entries exist. |
| `test_shares.py` | 54 | Key shares (§6.7.0). SFIES archiving, the misspelled member name, the seven-part signature. |
| `test_escrow.py` | 47 | The escrow listing and KeyVault framing. Padded sections declare their true length and occupy more. |
| `test_join.py` | 43 | Join messages (§6.9). Four fields that fail silently — signatures over bytes not messages, reserved field numbers, `string` vs `bytes`. |
| `test_cloudkit.py` | 43 | CloudKit transport and records (Stage 4). Protobuf framing, request shapes. |
| `test_enrolment.py` | 42 | Escrow enrolment (§4.5): pinned roots, the blob, the metadata spellings. Mints its own CA. |
| `test_bottle.py` | 31 | A bottled peer's key derivation (§6.7 step 2). |
| `test_session.py` | 35 | The session facade: ordering, that a join is never retried, and which of a peer's ids the circle answers to (#140). |
| `test_recovery.py` | 24 | Escrow recovery (§6.1–§6.5). The exchange itself needs a real passcode; this is everything around it. |
| `test_peers.py` | 24 | The trust-circle directory (§5.3): identifiers, signatures, vouchers. |
| `test_terms.py` | 22 | The terms-of-service flow (Stage 2 §5.2). |
| `test_device_identity.py` | 18 | One device across every header, the ids a client supplies, and the one user agent that deliberately disagrees. |
| `test_tls.py` | 15 | Verification on unless explicitly turned off, and the lazy scanner import. |
| `test_account_pet.py` | 16 | Issuing a fresh PET, and what a refused announce reports. |
| `test_icloud.py` | 14 | Wiring only, over sentinel fakes. Says so in its docstring. |
| `test_location_reports.py` | 22 | The last hop: encrypted payload → latitude and longitude. Both payload shapes; signed coordinates. |
| `test_golden.py` | 9 | Freezes the transcripts below. |
| `test_end_to_end.py` | 8 | A whole synthetic account, peer to accessories, in both shapes an account comes in. Built by `fake_account.py`. |
| `test_joined_peer.py` | 12 | Resuming as a peer that already joined: what is kept, and that the reading path asks for nothing more. |
| `test_timeouts.py` | 9 | How long a request may take, and what it says when it does not. Drives a local server that never answers. |

## `fake_account.py`

A whole account, layered as a real one is: keychain key → zone protection → record
protection → fields. Describe what it holds and run the real pipeline over it.

```python
account = a_whole_account([Accessory(name="Backpack")], label_suffix=DIVERGENT_LABEL_SUFFIX)
account.use_the_view(monkeypatch)
found = await account.accessories()      # recovered peer → shares → keys → accessories
```

- **Two account shapes, both real.** `AGREEING_LABEL_SUFFIX` is an account whose escrow
  label suffix already is the peer hash the circle knows; `DIVERGENT_LABEL_SUFFIX` is one
  where it is not (#140). That single difference decided whether any keys were recovered at
  all, so both shapes run the same pipeline and must reach the same accessories.
- **Add a shape rather than a test.** A new `Accessory(...)` field or a new variant is
  usually all a newly-discovered account shape needs.
- **Generated, not captured.** Every layer is encrypted under someone's keys, so a real
  account's bytes are neither readable without their private keys nor ours to commit. This
  proves the pipeline handles a shape; it cannot prove Apple produces one.

## `golden/`

Transcripts of what the writers produce, committed as text.

- **The digest is the assertion; the structure is for review.** A blob would be
  unreviewable — anything can hide in hex — so these show nesting, tags, lengths and field
  names, and a diff reads `escrowedSPKI grew 32 bytes`.
- **They are derived, so they cannot be hand-edited.** Change one and it stops matching what
  the builders produce.
- **The describers are separate readers** (`golden.py`), not the library's. A transcript
  produced by the parser being checked would agree with it by construction.
- **Key material is a length and a digest, never itself.** These get pasted into issues, and
  a test asserts it.
- **Inputs are fixed** — fixed keys, fixed timestamp, fixed salt. Randomised parts are named
  and excluded rather than dropped quietly; a permanent info's ECDSA signature is not frozen,
  its signed bytes are.

## Two habits

- **Check a test can fail.** Break the thing on purpose. The golden files and
  `test_location_reports.py` were verified this way, with three deliberate breaks — the
  85-byte branch, an unsigned latitude, one character of `SecureBackupUsesMultipleiCSCs` —
  each failing exactly the test that should have caught it.
- **`from test_pcs import …` in `test_beacons.py` is the only cross-file import.** There is
  no `conftest.py` and no shared factories; `FakeAccount`, `FakeHttp` and `a_record` are each
  defined independently in several files. Worth consolidating, not yet done.
