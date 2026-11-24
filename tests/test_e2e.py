"""Envelope seal/open (spec sections 7 and 7.1), without a connection."""

from __future__ import annotations

import json

import pytest

from gateway_client import e2e
from gateway_client.e2e import E2EError, KeyPair, ReplayGuard

NOW = 1_800_000_000.0


def _fields(**over):
    base = e2e.header(user_id="u1", client_id="c1", service="svc", tool="echo")
    return {**base, **over}


def _pair():
    return KeyPair.generate(), KeyPair.generate()


def test_round_trip_and_kid_names_sender():
    client, service = _pair()
    env = e2e.seal({"text": "hi"}, sender=client, recipient_public_raw=service.public_raw,
                   fields=_fields(), now=NOW)
    assert set(env) == e2e.FIELDS
    assert env["alg"] == "X25519-HKDF-SHA256-ChaCha20Poly1305" and env["mode"] == "auth"
    assert env["kid"] == client.kid == e2e.key_id(client.public_raw)
    assert len(e2e.b64url_decode(env["nonce"])) == 16 and env["sent_at"] == int(NOW)
    got = e2e.open_envelope(env, recipient=service, sender_public_raw=client.public_raw,
                            fields=_fields(), now=NOW + 1)
    assert got == {"text": "hi"}


def test_associated_data_is_sorted_compact_utf8():
    aad = e2e.associated_data(_fields(), "Tk9OQ0U", 5)
    assert aad == (b'{"client_id":"c1","contract_version":2,"encryption":"end-to-end",'
                   b'"nonce":"Tk9OQ0U","sent_at":5,"service":"svc","tool":"echo",'
                   b'"user_id":"u1"}')
    reply = e2e.reply_header(_fields(), "r1")
    assert json.loads(e2e.associated_data(reply, "n", 1))["direction"] == "reply"
    assert json.loads(e2e.associated_data(reply, "n", 1))["request_id"] == "r1"


@pytest.mark.parametrize("tamper", [
    {"tool": "other"}, {"user_id": "u2"}, {"client_id": "c2"}, {"service": "x"},
    {"encryption": "none"},
])
def test_tampered_header_is_refused(tamper):
    client, service = _pair()
    env = e2e.seal({}, sender=client, recipient_public_raw=service.public_raw,
                   fields=_fields(), now=NOW)
    with pytest.raises(E2EError) as exc:
        e2e.open_envelope(env, recipient=service, sender_public_raw=client.public_raw,
                          fields=_fields(**tamper), now=NOW)
    assert exc.value.code == "bad_arguments"


def test_wrong_kid_refused():
    client, service = _pair()
    other = KeyPair.generate()
    env = e2e.seal({}, sender=client, recipient_public_raw=service.public_raw,
                   fields=_fields(), now=NOW)
    with pytest.raises(E2EError, match="kid") as exc:
        e2e.open_envelope(env, recipient=service, sender_public_raw=other.public_raw,
                          fields=_fields(), now=NOW)
    assert exc.value.code == "bad_arguments"


def test_wrong_sender_key_with_forged_kid_fails_auth():
    client, service = _pair()
    impostor = KeyPair.generate()
    env = e2e.seal({}, sender=impostor, recipient_public_raw=service.public_raw,
                   fields=_fields(), now=NOW)
    env["kid"] = client.kid  # claims to be the client; Auth mode catches it
    with pytest.raises(E2EError) as exc:
        e2e.open_envelope(env, recipient=service, sender_public_raw=client.public_raw,
                          fields=_fields(), now=NOW)
    assert exc.value.code == "bad_arguments"


def test_reused_nonce_refused_within_window_per_client():
    client, service = _pair()
    guard = ReplayGuard()
    env = e2e.seal({}, sender=client, recipient_public_raw=service.public_raw,
                   fields=_fields(), now=NOW)
    kwargs = dict(recipient=service, sender_public_raw=client.public_raw, fields=_fields(),
                  replay=guard, replay_client_id="c1")
    e2e.open_envelope(env, now=NOW, **kwargs)
    with pytest.raises(E2EError, match="nonce") as exc:
        e2e.open_envelope(env, now=NOW + 60, **kwargs)
    assert exc.value.code == "not_allowed"


def test_replay_guard_window():
    guard = ReplayGuard()
    assert guard.claim("c1", "n", NOW)
    assert not guard.claim("c1", "n", NOW + 599)
    assert guard.claim("c2", "n", NOW + 1)          # per client
    assert guard.claim("c1", "n", NOW + 601)        # after 10 minutes


@pytest.mark.parametrize("offset", [301, -301, 3600])
def test_stale_or_future_sent_at_refused(offset):
    client, service = _pair()
    env = e2e.seal({}, sender=client, recipient_public_raw=service.public_raw,
                   fields=_fields(), now=NOW)
    with pytest.raises(E2EError, match="sent_at") as exc:
        e2e.open_envelope(env, recipient=service, sender_public_raw=client.public_raw,
                          fields=_fields(), now=NOW + offset)
    assert exc.value.code == "not_allowed"


def test_sent_at_within_five_minutes_accepted():
    client, service = _pair()
    env = e2e.seal({"a": 1}, sender=client, recipient_public_raw=service.public_raw,
                   fields=_fields(), now=NOW)
    assert e2e.open_envelope(env, recipient=service, sender_public_raw=client.public_raw,
                             fields=_fields(), now=NOW + 300) == {"a": 1}


@pytest.mark.parametrize("mutate", [
    lambda e: e.pop("nonce"),
    lambda e: e.update(extra=1),
    lambda e: e.update(alg="X"),
    lambda e: e.update(mode="base"),
    lambda e: e.update(kid="ABC"),
    lambda e: e.update(nonce=e2e.b64url_encode(b"short")),
    lambda e: e.update(sent_at="1"),
    lambda e: e.update(enc="!!"),
])
def test_bad_shape_refused(mutate):
    client, service = _pair()
    env = e2e.seal({}, sender=client, recipient_public_raw=service.public_raw,
                   fields=_fields(), now=NOW)
    mutate(env)
    with pytest.raises(E2EError) as exc:
        e2e.open_envelope(env, recipient=service, sender_public_raw=client.public_raw,
                          fields=_fields(), now=NOW)
    assert exc.value.code == "bad_arguments"


def test_keypair_round_trip_and_repr_hides_private():
    pair = KeyPair.generate()
    again = KeyPair.from_private_b64(pair.private_b64())
    assert again.public_raw == pair.public_raw
    assert pair.private_b64() not in repr(pair)


@pytest.mark.parametrize("bad_key", [
    b"\x00" * 32,                 # all-zero key
    b"\x01" + b"\x00" * 31,       # order 2 point
    b"\x00" * 16,                 # invalid length
    "not-bytes",                  # invalid type
])
def test_check_public_key_refuses_small_order_and_invalid(bad_key):
    with pytest.raises(ValueError, match="public key is a small-order X25519 point"):
        e2e.check_public_key(bad_key)


def test_check_public_key_accepts_valid():
    pair = KeyPair.generate()
    # Does not raise
    e2e.check_public_key(pair.public_raw)


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_open_envelope_rejects_nonfinite_json_constants(constant):
    client, service = _pair()
    nonce = e2e.b64url_encode(b"\x01" * 16)
    sent_at = int(NOW)
    fields = _fields()
    enc, ctx = e2e._SUITE.create_sender_context(
        e2e._kem_public(service.public_raw), info=e2e.HPKE_INFO, sks=e2e._kem_private(client)
    )
    ct = ctx.seal(f'{{"amount": {constant}}}'.encode("utf-8"),
                  aad=e2e.associated_data(fields, nonce, sent_at))
    env = {
        "alg": e2e.ALG, "mode": e2e.MODE, "kid": client.kid,
        "enc": e2e.b64url_encode(enc), "ct": e2e.b64url_encode(ct),
        "nonce": nonce, "sent_at": sent_at,
    }
    with pytest.raises(E2EError) as exc:
        e2e.open_envelope(env, recipient=service, sender_public_raw=client.public_raw,
                          fields=fields, now=sent_at)
    assert exc.value.code == "bad_arguments"


@pytest.mark.parametrize("bad_val", [float("nan"), float("inf"), float("-inf")])
def test_canonical_json_and_seal_reject_nonfinite_floats(bad_val):
    client, service = _pair()
    with pytest.raises(ValueError):
        e2e.canonical_json({"x": bad_val})
    with pytest.raises(ValueError):
        e2e.seal({"x": bad_val}, sender=client, recipient_public_raw=service.public_raw,
                 fields=_fields(), now=NOW)


def test_open_envelope_deeply_nested_json_raises_e2e_bad_arguments():
    client, service = _pair()
    nonce = e2e.b64url_encode(b"\x01" * 16)
    sent_at = int(NOW)
    fields = _fields()
    enc, ctx = e2e._SUITE.create_sender_context(
        e2e._kem_public(service.public_raw), info=e2e.HPKE_INFO, sks=e2e._kem_private(client)
    )
    deep = b'{"a":' * 10000 + b"1" + b"}" * 10000
    ct = ctx.seal(deep, aad=e2e.associated_data(fields, nonce, sent_at))
    env = {
        "alg": e2e.ALG, "mode": e2e.MODE, "kid": client.kid,
        "enc": e2e.b64url_encode(enc), "ct": e2e.b64url_encode(ct),
        "nonce": nonce, "sent_at": sent_at,
    }
    with pytest.raises(E2EError) as exc:
        e2e.open_envelope(env, recipient=service, sender_public_raw=client.public_raw,
                          fields=fields, now=sent_at)
    assert exc.value.code == "bad_arguments"


def test_replay_guard_evicts_expired_client_buckets_and_handles_concurrent_reuse():
    from concurrent.futures import ThreadPoolExecutor

    guard = ReplayGuard(window=600)
    for i in range(1000):
        assert guard.claim(f"c-{i}", "n1", now=0.0) is True
    assert guard.claim("other_client", "n", now=601.0) is True
    assert len(guard._seen) == 1

    # Expired nonce is still accepted even within <1s before next global sweep
    subsec_guard = ReplayGuard(window=0.2)
    assert subsec_guard.claim("c1", "n1", now=100.0) is True
    assert subsec_guard.claim("c1", "n1", now=100.3) is True

    # Concurrent reuse of non-expired nonce yields exactly one True
    conc_guard = ReplayGuard(window=600)
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: conc_guard.claim("c1", "same", now=10.0), range(16)))
    assert results.count(True) == 1
    assert results.count(False) == 15
