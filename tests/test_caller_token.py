"""GW-3 caller-token verification (INT-C3), without a connection: one test
per failure mode, plus the key-set cache (fetch, cache, refetch on an unknown
kid, bounded refetch rate)."""

from __future__ import annotations

import pytest
from helpers import APP, PRINCIPAL, Issuer, run

from gateway_client import caller_token as ct
from gateway_client.caller_token import CallerTokenVerifier, KeySet, TokenRefused

NOW = 1_800_000_000.0


class Clock:
    def __init__(self, t: float = NOW) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


class Fetcher:
    """A JWKS endpoint that counts its fetches and can fail or change keys."""

    def __init__(self, *issuers: Issuer) -> None:
        self.issuers = list(issuers)
        self.urls: list[str] = []
        self.fail = False

    def __call__(self, url: str) -> dict:
        self.urls.append(url)
        if self.fail:
            raise OSError("connection refused")
        return {"keys": [k for i in self.issuers for k in i.jwks()["keys"]]}

    @property
    def count(self) -> int:
        return len(self.urls)


def _verifier(fetch, clock=None, **kw) -> CallerTokenVerifier:
    clock = clock or Clock()
    keys = KeySet("https://gw.test/.well-known/jwks.json", fetch=fetch, clock=clock,
                  **{k: kw.pop(k) for k in ("min_refetch_interval", "max_age") if k in kw})
    return CallerTokenVerifier("svc", keys, clock=clock, **kw)


def _refused(verifier, token) -> TokenRefused:
    with pytest.raises(TokenRefused) as exc:
        run(verifier.verify(token))
    return exc.value


# --- the happy path ------------------------------------------------------------------

def test_valid_token_yields_principal_app_and_raw_token():
    issuer = Issuer()
    fetch = Fetcher(issuer)
    token = issuer.token(now=NOW)
    verified = run(_verifier(fetch).verify(token))
    assert verified.principal == PRINCIPAL
    assert verified.app == APP
    assert verified.token == token
    assert verified.claims["aud"] == "svc" and verified.claims["jti"]
    assert fetch.urls == ["https://gw.test/.well-known/jwks.json"]
    assert token not in repr(verified)


# --- one test per failure mode (all refused not_allowed) -----------------------------

def test_bad_signature_refused():
    issuer, forger = Issuer(), Issuer()
    # Signed by a different key under the published kid.
    token = forger.token(now=NOW, kid=issuer.kid)
    err = _refused(_verifier(Fetcher(issuer)), token)
    assert err.code == "not_allowed" and "signature" in err.reason


def test_tampered_payload_refused():
    issuer = Issuer()
    head, body, sig = issuer.token(now=NOW).split(".")
    other = issuer.token(now=NOW, sub="wrn:wolf-access:user/u-mallory").split(".")[1]
    err = _refused(_verifier(Fetcher(issuer)), ".".join([head, other, sig]))
    assert err.code == "not_allowed"


def test_wrong_audience_refused():
    issuer = Issuer()
    err = _refused(_verifier(Fetcher(issuer)), issuer.token(now=NOW, aud="other-svc"))
    assert err.code == "not_allowed" and "audience" in err.reason


def test_audience_list_refused_even_when_it_names_this_service():
    issuer = Issuer()
    err = _refused(_verifier(Fetcher(issuer)), issuer.token(now=NOW, aud=["svc", "x"]))
    assert err.code == "not_allowed" and "audience" in err.reason


def test_expired_refused():
    issuer = Issuer()
    token = issuer.token(now=NOW - 120, ttl=60)
    err = _refused(_verifier(Fetcher(issuer)), token)
    assert err.code == "not_allowed" and "expired" in err.reason


def test_small_clock_skew_tolerated_but_not_more():
    issuer = Issuer()
    token = issuer.token(now=NOW - 65, ttl=60)  # expired 5 s ago
    assert run(_verifier(Fetcher(issuer)).verify(token)).principal == PRINCIPAL
    token = issuer.token(now=NOW - 80, ttl=60)  # expired 20 s ago
    assert _refused(_verifier(Fetcher(issuer)), token).code == "not_allowed"


def test_lifetime_beyond_sixty_seconds_refused():
    issuer = Issuer()
    err = _refused(_verifier(Fetcher(issuer)), issuer.token(now=NOW, ttl=3600))
    assert err.code == "not_allowed" and "lifetime" in err.reason


@pytest.mark.parametrize("claim", ["sub", "act", "aud", "exp", "jti"])
def test_missing_claim_refused(claim):
    issuer = Issuer()
    err = _refused(_verifier(Fetcher(issuer)), issuer.token(now=NOW, drop=(claim,)))
    assert err.code == "not_allowed"


@pytest.mark.parametrize("claim,value", [("sub", ""), ("act", "  "), ("jti", 7),
                                         ("sub", ["x"])])
def test_blank_or_non_string_identity_claim_refused(claim, value):
    issuer = Issuer()
    err = _refused(_verifier(Fetcher(issuer)), issuer.token(now=NOW, **{claim: value}))
    assert err.code == "not_allowed"


def test_replayed_jti_refused():
    issuer = Issuer()
    verifier = _verifier(Fetcher(issuer))
    token = issuer.token(now=NOW)
    run(verifier.verify(token))
    err = _refused(verifier, token)
    assert err.code == "not_allowed" and "replayed" in err.reason


def test_replay_cache_forgets_a_jti_only_after_the_token_expired():
    issuer, clock = Issuer(), Clock()
    verifier = _verifier(Fetcher(issuer), clock=clock)
    token = issuer.token(now=NOW, ttl=60, jti="j-1")
    run(verifier.verify(token))
    clock.t = NOW + 60 + ct.DEFAULT_LEEWAY_SECONDS + 1
    # The token itself is now expired, and the cache entry has been dropped.
    assert "expired" in _refused(verifier, token).reason
    assert verifier.replay_cache_size == 0


@pytest.mark.parametrize("token", [None, "", 42, "not-a-jwt", "a.b.c"])
def test_missing_or_malformed_token_refused(token):
    err = _refused(_verifier(Fetcher(Issuer())), token)
    assert err.code == "not_allowed"


def test_other_algorithm_refused():
    issuer = Issuer()
    err = _refused(_verifier(Fetcher(issuer)), issuer.hs256_token(now=NOW))
    assert err.code == "not_allowed"


def test_token_without_kid_refused():
    issuer = Issuer()
    err = _refused(_verifier(Fetcher(issuer)), issuer.token(now=NOW, kid=None))
    assert err.code == "not_allowed" and "kid" in err.reason


# --- key set: cache, refetch on unknown kid, bounded rate ----------------------------

def test_key_set_is_cached_across_calls():
    issuer = Issuer()
    fetch = Fetcher(issuer)
    verifier = _verifier(fetch)
    for _ in range(5):
        run(verifier.verify(issuer.token(now=NOW)))
    assert fetch.count == 1


def test_unknown_kid_refetches_then_verifies():
    old, new = Issuer(), Issuer()
    fetch, clock = Fetcher(old), Clock()
    verifier = _verifier(fetch, clock=clock)
    run(verifier.verify(old.token(now=NOW)))
    fetch.issuers = [new]          # the gateway rotated its key
    clock.t += ct.DEFAULT_MIN_REFETCH_SECONDS
    assert run(verifier.verify(new.token(now=clock.t))).principal == PRINCIPAL
    assert fetch.count == 2


def test_unknown_kid_refetch_is_rate_limited():
    issuer, stranger = Issuer(), Issuer()
    fetch, clock = Fetcher(issuer), Clock()
    verifier = _verifier(fetch, clock=clock)
    run(verifier.verify(issuer.token(now=NOW)))
    for _ in range(20):            # a flood of tokens under an unknown kid
        err = _refused(verifier, stranger.token(now=NOW))
        assert err.code == "not_allowed" and "kid" in err.reason
    assert fetch.count == 1        # no refetch inside the interval
    clock.t += ct.DEFAULT_MIN_REFETCH_SECONDS
    _refused(verifier, stranger.token(now=clock.t))
    assert fetch.count == 2        # one refetch once the interval passed


def test_concurrent_unknown_kid_calls_share_one_fetch():
    import asyncio
    issuer = Issuer()
    fetch = Fetcher(issuer)
    verifier = _verifier(fetch)

    async def many():
        return await asyncio.gather(*(verifier.verify(issuer.token(now=NOW))
                                      for _ in range(10)))
    assert len(run(many())) == 10
    assert fetch.count == 1


def test_key_set_unreachable_is_unavailable():
    issuer = Issuer()
    fetch = Fetcher(issuer)
    fetch.fail = True
    err = _refused(_verifier(fetch), issuer.token(now=NOW))
    assert err.code == "unavailable"


def test_stale_key_set_kept_when_refresh_fails():
    issuer, clock = Issuer(), Clock()
    fetch = Fetcher(issuer)
    verifier = _verifier(fetch, clock=clock)
    run(verifier.verify(issuer.token(now=NOW)))
    clock.t += ct.DEFAULT_MAX_AGE_SECONDS + 1
    fetch.fail = True
    assert run(verifier.verify(issuer.token(now=clock.t))).principal == PRINCIPAL
    assert fetch.count == 2        # it tried to refresh


def test_key_set_refreshed_after_max_age():
    issuer, clock = Issuer(), Clock()
    fetch = Fetcher(issuer)
    verifier = _verifier(fetch, clock=clock)
    run(verifier.verify(issuer.token(now=NOW)))
    clock.t += ct.DEFAULT_MAX_AGE_SECONDS + 1
    run(verifier.verify(issuer.token(now=clock.t)))
    assert fetch.count == 2


def test_removed_key_is_no_longer_accepted_after_refresh():
    old, new = Issuer(), Issuer()
    fetch, clock = Fetcher(old), Clock()
    verifier = _verifier(fetch, clock=clock)
    run(verifier.verify(old.token(now=NOW)))
    fetch.issuers = [new]
    clock.t += ct.DEFAULT_MAX_AGE_SECONDS + 1
    assert _refused(verifier, old.token(now=clock.t)).code == "not_allowed"


def test_non_ed25519_keys_in_the_set_are_ignored():
    issuer = Issuer()

    def fetch(url):
        return {"keys": [{"kty": "RSA", "kid": issuer.kid, "n": "AQAB", "e": "AQAB"},
                         {"kty": "OKP", "crv": "X25519", "kid": "x", "x": "AAAA"},
                         "garbage"]}
    err = _refused(_verifier(fetch), issuer.token(now=NOW))
    assert err.code == "not_allowed" and "kid" in err.reason


@pytest.mark.parametrize("body", [[], {"keys": "x"}, "nope", None])
def test_malformed_key_set_is_unavailable(body):
    err = _refused(_verifier(lambda url: body), Issuer().token(now=NOW))
    assert err.code == "unavailable"


def test_async_fetch_supported():
    issuer = Issuer()

    async def fetch(url):
        return issuer.jwks()
    assert run(_verifier(fetch).verify(issuer.token(now=NOW))).app == APP


# --- the JWKS URL -------------------------------------------------------------------

@pytest.mark.parametrize("backend,jwks", [
    ("wss://gw.example/backend", "https://gw.example/.well-known/jwks.json"),
    ("ws://127.0.0.1:8000/backend", "http://127.0.0.1:8000/.well-known/jwks.json"),
    ("wss://gw.example/prefix/backend", "https://gw.example/prefix/.well-known/jwks.json"),
    ("wss://gw.example", "https://gw.example/.well-known/jwks.json"),
])
def test_jwks_url_derived_from_backend_url(backend, jwks):
    assert ct.jwks_url_for(backend) == jwks
