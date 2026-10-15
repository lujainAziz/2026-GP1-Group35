# Local integration with the Nora backend snapshot

Source: `Assas-main (9).zip`, supplied by the project owner. Imported API,
discovery/classification code, their tests and API/schema documentation. This
is a local file integration; it does not advance or push any remote Git branch.

## Device names

The mobile repository uses `PUT /devices/{mac}/name` with `{"name": text}`
or `{"name": null}` to clear. Both list and detail read `user_name`; a missing
custom name falls back to hostname/model. The freshest list owns explicit
cleared names and trust state instead of falling back to stale detail values.

## Pairing additions beyond the supplied backend snapshot

The snapshot supports device renaming but lacks the phone-name/session-list
contract already used by the frontend. Local integration adds:

- Optional `device_name` to `POST /pair`, trimmed, maximum 40 characters.
  Missing/blank uses `Unnamed phone`. Existing session tables receive an
  additive `device_name` column on the next successful pairing; IDs and token
  hashes are preserved.
- `GET /sessions` returns `[{id, device_name, created_at}]` ordered by ID.
  Only appliance-local requests may use it; no token or hash is returned.
  A legacy session has the fallback name. A missing table returns `[]`.

Review and deploy these local additions together with the frontend before
testing named-phone banners on the physical appliance.

## Runtime configuration

Mobile preview remains in demo mode by default. For the real appliance:

```sh
flutter run --dart-define=ASSAS_DEMO=false
```

It keeps the existing DNS-SD/mDNS resolution. For an explicit address, add
`--dart-define=ASSAS_API_BASE_URL=http://APPLIANCE_ADDRESS:8000`.
The display continues to use the local API at `http://127.0.0.1:8000` by
default; `--dart-define=ASSAS_DEMO=true` is only for preview.

## Verification

Backend: `python -m unittest test_api test_frontend_contract -q` tests the
HTTP contract, pairing, naming, clearing, session revocation and legacy schema.
The original discovery/classification suites are also run separately.

The Flutter test `test/live_backend_contract_test.dart` runs real repository
calls against an isolated local FastAPI server when `ASSAS_INTEGRATION_URL`
is supplied; otherwise it is skipped. No appliance database is used.
