"""GW-3 caller tokens: the only source of caller identity (INT-C3).

For every routed call the gateway sends a `caller_token`: a JWT signed EdDSA
(Ed25519) under a key in the gateway's key set at `/.well-known/jwks.json`
(header `kid`), with claims

    sub  the principal the call acts as (a WRN)
    act  the connected app the call came through (a WRN)
    aud  this service's name
    iat, exp (exp at most 60 s after iat), jti

`CallerTokenVerifier.verify` checks, in order, and raises `TokenRefused` on
the first failure:

1. the token is a compact JWS whose header names `alg: EdDSA` and a `kid`;
2. `kid` is a key in the key set (`KeySet`; an unknown kid triggers one
   rate-limited refetch, for a gateway that rotated its key);
3. the signature verifies under that key;
4. `sub`, `act`, `aud`, `exp` and `jti` are present; `sub`, `act` and `jti`
   are non-blank strings; `aud` is a string equal to this service's name (a
   list is refused even when it names the service: the token is for one
   backend);
5. `exp` has not passed, allowing `leeway` seconds of clock skew, and is no
   more than 60 s plus `leeway` ahead (GW-3's maximum lifetime);
6. `jti` has not been accepted before while the token could still be valid
   (an in-memory cache, entries dropped once the token has expired).

Refusals are `not_allowed`, except when the key set could not be fetched at
all (no keys cached, or a refetch for an unknown kid failed), which is
`unavailable`: the token was not checked, so a retry may succeed.

Key set cache: fetched on first use, kept for `max_age` seconds (default one
hour), refreshed after that when a token is checked; a failed refresh keeps
the cached keys. Fetches are at least `min_refetch_interval` seconds apart
(default 10 s), so a flood of tokens under an unknown kid causes one fetch,
not one per token; concurrent checks share one fetch. Only Ed25519 (`kty
OKP`, `crv Ed25519`) keys with a `kid` are used.

Nothing here logs; a refusal's `reason` names the check that failed, never a
token or claim value.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import time
import urllib.request
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Awaitable, Callable, Mapping
from urllib.parse import urlsplit, urlunsplit

import jwt

from .errors import NOT_ALLOWED, UNAVAILABLE

ALGORITHM = "EdDSA"
REQUIRED_CLAIMS = ("sub", "act", "aud", "exp", "jti")
MAX_TTL_SECONDS = 60                  # GW-3: exp is at most 60 s
DEFAULT_LEEWAY_SECONDS = 10           # clock skew allowed on exp
DEFAULT_MIN_REFETCH_SECONDS = 10.0    # at most one key-set fetch per 10 s
DEFAULT_MAX_AGE_SECONDS = 3600.0      # refresh a key set older than an hour
FETCH_TIMEOUT_SECONDS = 5.0
MAX_JWKS_BYTES = 64 * 1024
JWKS_PATH = "/.well-known/jwks.json"

FETCHED, FAILED, SKIPPED = "fetched", "failed", "skipped"

Fetch = Callable[[str], "dict | Awaitable[dict]"]


class TokenRefused(Exception):
    """The caller token was refused. `code` is the section 6.3 code to
    answer with (`not_allowed`, or `unavailable` when the key set could not
    be fetched); `reason` names the failed check, never a value."""

    def __init__(self, reason: str, code: str = NOT_ALLOWED) -> None:
        super().__init__(reason)
        self.reason = reason
        self.code = code


@dataclass(frozen=True)
class VerifiedToken:
    """A caller token that passed every check."""

    principal: str                      # `sub`
    app: str                            # `act`
    token: str = field(repr=False)      # the compact JWT, for forwarding
    claims: Mapping[str, Any] = field(repr=False)


def jwks_url_for(backend_url: str) -> str:
    """The gateway's key-set URL on the same host as its `/backend`
    WebSocket URL: `wss://` becomes `https://`, `ws://` `http://`, and a
    trailing `/backend` is replaced by `/.well-known/jwks.json`."""
    parts = urlsplit(backend_url)
    scheme = {"wss": "https", "ws": "http"}.get(parts.scheme, parts.scheme)
    path = parts.path.rstrip("/")
    if path.endswith("/backend"):
        path = path[: -len("/backend")]
    return urlunsplit((scheme, parts.netloc, path + JWKS_PATH, "", ""))


def fetch_jwks(url: str) -> dict:
    """GET `url` and parse it as JSON (blocking; run in a worker thread)."""
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=FETCH_TIMEOUT_SECONDS) as response:  # noqa: S310
        body = response.read(MAX_JWKS_BYTES + 1)
    if len(body) > MAX_JWKS_BYTES:
        raise ValueError("key set is too large")
    return json.loads(body)


def _ed25519_keys(document: Any) -> dict[str, jwt.PyJWK]:
    """The Ed25519 keys of a JWKS document by kid. ValueError when the
    document is not a key set."""
    if not isinstance(document, dict) or not isinstance(document.get("keys"), list):
        raise ValueError("not a JWKS document")
    keys: dict[str, jwt.PyJWK] = {}
    for entry in document["keys"]:
        if not (isinstance(entry, dict) and entry.get("kty") == "OKP"
                and entry.get("crv") == "Ed25519"
                and isinstance(entry.get("kid"), str) and entry["kid"]):
            continue
        try:
            keys[entry["kid"]] = jwt.PyJWK(entry, algorithm=ALGORITHM)
        except (jwt.PyJWTError, ValueError, TypeError, KeyError):
            continue
    return keys


class KeySet:
    """The gateway's key set, cached (module docstring)."""

    def __init__(self, url: str, *, fetch: Fetch | None = None,
                 min_refetch_interval: float = DEFAULT_MIN_REFETCH_SECONDS,
                 max_age: float = DEFAULT_MAX_AGE_SECONDS,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.url = url
        self._fetch = fetch or fetch_jwks
        self._min_interval = min_refetch_interval
        self._max_age = max_age
        self._clock = clock
        self._keys: dict[str, jwt.PyJWK] = {}
        self._loaded_at: float | None = None      # last successful fetch
        self._attempted_at: float | None = None   # last fetch attempt
        self._lock: asyncio.Lock | None = None
        self._lock_loop: asyncio.AbstractEventLoop | None = None
        self._generation = 0
        self._last_outcome = SKIPPED

    def _may_fetch(self) -> bool:
        return (self._attempted_at is None
                or self._clock() - self._attempted_at >= self._min_interval)

    def _stale(self) -> bool:
        return self._loaded_at is None or self._clock() - self._loaded_at >= self._max_age

    def _get_lock(self) -> asyncio.Lock:
        loop = asyncio.get_running_loop()
        if self._lock is None or self._lock_loop is not loop:
            self._lock, self._lock_loop = asyncio.Lock(), loop
        return self._lock

    async def _call_fetch(self) -> Any:
        if inspect.iscoroutinefunction(self._fetch):
            return await self._fetch(self.url)
        result = await asyncio.to_thread(self._fetch, self.url)
        if inspect.isawaitable(result):
            result = await result
        return result

    async def _refresh(self) -> str:
        """Fetch the key set once, unless the rate limit forbids it:
        FETCHED, FAILED (the cached keys are kept) or SKIPPED. A check that
        waited while another fetched shares that fetch's outcome."""
        generation = self._generation
        async with self._get_lock():
            if self._generation != generation:
                return self._last_outcome
            if not self._may_fetch():
                return SKIPPED
            self._attempted_at = self._clock()
            self._generation += 1
            try:
                keys = _ed25519_keys(await self._call_fetch())
            except Exception:  # network, JSON or shape: keep what is cached
                self._last_outcome = FAILED
                return FAILED
            self._keys, self._loaded_at = keys, self._attempted_at
            self._last_outcome = FETCHED
            return FETCHED

    async def key(self, kid: str) -> jwt.PyJWK:
        """The key named `kid`. TokenRefused(not_allowed) when the set has no
        such key; TokenRefused(unavailable) when the set could not be fetched
        to find out."""
        outcome: str | None = None
        if self._stale():
            outcome = await self._refresh()
            if self._loaded_at is None:
                raise TokenRefused("the gateway key set could not be fetched", UNAVAILABLE)
        if kid in self._keys:
            return self._keys[kid]
        if outcome is None:  # unknown kid: one (rate-limited) refetch
            outcome = await self._refresh()
            if kid in self._keys:
                return self._keys[kid]
        if outcome == FAILED:
            raise TokenRefused("the gateway key set could not be fetched", UNAVAILABLE)
        raise TokenRefused("kid is not in the gateway key set")


class CallerTokenVerifier:
    """Checks GW-3 caller tokens for one service (module docstring)."""

    def __init__(self, audience: str, key_set: KeySet, *,
                 leeway: float = DEFAULT_LEEWAY_SECONDS,
                 clock: Callable[[], float] = time.time) -> None:
        self.audience = audience
        self.key_set = key_set
        self._leeway = leeway
        self._clock = clock
        self._seen: dict[str, float] = {}   # jti -> when it may be forgotten
        self._purged_at = float("-inf")

    @property
    def replay_cache_size(self) -> int:
        return len(self._seen)

    def _forget_expired(self, now: float) -> None:
        """Drop jtis whose tokens can no longer be valid; at most once a
        second, so a busy service does not scan the cache on every call."""
        if now - self._purged_at < 1.0:
            return
        self._purged_at = now
        for jti in [j for j, until in self._seen.items() if until <= now]:
            del self._seen[jti]

    async def verify(self, token: Any) -> VerifiedToken:
        """The verified token, else TokenRefused."""
        now = self._clock()
        self._forget_expired(now)
        if not isinstance(token, str) or not token:
            raise TokenRefused("no caller_token")
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError:
            raise TokenRefused("caller_token is not a JWT") from None
        if header.get("alg") != ALGORITHM:
            raise TokenRefused("caller_token is not signed EdDSA")
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise TokenRefused("caller_token header has no kid")
        key = await self.key_set.key(kid)
        claims = self._decode(token, key, now)
        self._check_claims(claims, now)
        jti = claims["jti"]
        if jti in self._seen:
            raise TokenRefused("caller_token was replayed (jti already used)")
        self._seen[jti] = float(claims["exp"]) + self._leeway
        return VerifiedToken(principal=claims["sub"], app=claims["act"], token=token,
                             claims=MappingProxyType(dict(claims)))

    def _decode(self, token: str, key: jwt.PyJWK, now: float) -> dict[str, Any]:
        try:
            return jwt.decode(
                token, key.key, algorithms=[ALGORITHM], audience=self.audience,
                leeway=self._leeway,
                options={"require": list(REQUIRED_CLAIMS), "verify_iat": False,
                         "verify_nbf": False, "verify_exp": False})
        except jwt.InvalidSignatureError:
            raise TokenRefused("caller_token signature does not verify") from None
        except jwt.MissingRequiredClaimError as exc:
            raise TokenRefused(f"caller_token has no {exc.claim} claim") from None
        except jwt.InvalidAudienceError:
            raise TokenRefused("caller_token audience is not this service") from None
        except jwt.PyJWTError:
            raise TokenRefused("caller_token is malformed") from None

    def _check_claims(self, claims: dict[str, Any], now: float) -> None:
        if claims.get("aud") != self.audience:
            raise TokenRefused("caller_token audience is not this service")
        for name in ("sub", "act", "jti"):
            value = claims.get(name)
            if not isinstance(value, str) or not value.strip():
                raise TokenRefused(f"caller_token {name} is not a non-empty string")
        exp = claims.get("exp")
        if isinstance(exp, bool) or not isinstance(exp, (int, float)):
            raise TokenRefused("caller_token exp is not a number")
        if exp + self._leeway < now:
            raise TokenRefused("caller_token has expired")
        if exp - now > MAX_TTL_SECONDS + self._leeway:
            raise TokenRefused("caller_token lifetime exceeds 60 seconds")
