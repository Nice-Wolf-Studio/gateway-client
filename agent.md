# gateway-client — working notes for agents

This file provides load-bearing working notes and operational guidelines for AI agents working in `Nice-Wolf-Studio/gateway-client`. Every claim below reflects the `main` and `development` tree. If a behavior or convention changes, update this file in the same PR.

---

## 1. Branch Model & GitHub Rulesets

- **`development` is the active integration branch.** All feature branches, bugfixes, and refactors branch from `origin/development` and open PRs targeting `development`.
- **`main` is production and the default GitHub branch.** 
  - `development` is promoted to `main` at release milestones via a promotion PR (`development → main`).
  - Promotion PRs merge with a merge commit (`gh pr merge <num> --merge`), not squash, preserving individual commit history between branches.
- **GitHub Rulesets (`platform-main` and `platform-development`):**
  - Direct pushes, deletions, and force-pushes are blocked.
  - Every change lands via a PR.
  - PR branches must be up-to-date with their base branch (`strict_required_status_checks_policy: true`).
  - Mandatory CI status checks required to pass:
    - `ci/pytest (3.10)`
    - `ci/pytest (3.12)`
  - No approving review count required (`required_approving_review_count: 0`).

---

## 2. Issue Tracking & Auto-Close Semantics

- **Auto-close only fires on merges to `main`.** Because feature PRs merge into `development`, GitHub's `Closes #N` or `Fixes #N` keywords do **not** automatically close issues upon merging to `development`.
- Issues auto-close when `development` is promoted into `main`. If working outside milestone promotions, verify issue states with `gh issue view <num>` or manually close them once verified.

---

## 3. Architecture & Core Invariants

`gateway-client` is the official Python client library for backend services connecting to `mcp-gateway` over WebSockets (Contract v2).

### 3.1. Contract v2 Verification & Check Order
When a frame arrives, `GatewayService._reply` enforces this strict precedence:
1. **`caller_token` verification (`_verify_caller`)** → failure yields `not_allowed` (`caller token refused`). Identity claims (`sub`, `act`, `jti`) and header `kid` are validated via `_check_id_str`: must be non-blank `str`, no leading/trailing whitespace, and zero Unicode `Cc` (control) or `Cf` (format) characters. Claims are never normalized.
2. **`encryption` mode check** (`none` or `end-to-end`) → invalid yields `bad_arguments`.
3. **Client key & AAD header check (`_client_key`)** in `end-to-end` mode → validates key shape and tests X25519 Diffie-Hellman exchange (`check_public_key`). Unsealable or small-order keys are rejected with `bad_arguments` before binding or pinning.
4. **Target validation (`_check_target`)** → missing or undeclared tool/resource yields `not_found`.
5. **Payload handling & downgrade pinning**:
   - Connected apps (`caller.app` / `act` WRN) seen in `end-to-end` mode are recorded in `self._pinned`.
   - Subsequent `none` calls from a pinned app are refused with `not_allowed`.

### 3.2. Statelessness & Pin Persistence (Q2 / D2)
- **Stateless by default**: In-memory pinning (`self._pinned: set[str] = set()`) is the default, maintaining zero file side effects and preventing permanent lockouts if an operator toggles an app's encryption in `mcp-gateway`.
- **Opt-in persistence**: Set `SERVICE_PIN_STORE_FILE` in environment or pass `pin_store=FilePinStore(path)` to `GatewayService`. `FilePinStore` uses atomic file replacement (`mkstemp` + `fsync` + `os.replace`) with `0600` permissions.

### 3.3. Strict Privacy & Metadata-Only Logging Invariant
- **Never logged**: arguments, results, error text from handlers, `SERVICE_CREDENTIAL`, `SERVICE_PRIVATE_KEY`, or `Caller.token` (the raw JWT).
- **No heuristic redaction**: zero key-name pattern matching or partial masking.
- **Log injection protection**: all untrusted strings formatted into plain-text logs are escaped using `_safe_str` (`\r` → `\r`, `\n` → `\n`).
- **Structured call tracing**: routed requests emit `call.start` and `call.end` events capturing `request_id`, `tool`/`uri`, `principal`, `app`, `duration_ms`, and `outcome`. Setting `GATEWAY_LOG_FORMAT=json` outputs structured JSON logs.
- **Context helper**: `current_request_id()` returns the active request ID inside handlers across async boundaries, and `None` outside.

### 3.4. Application Tool Errors (`isError=True`)
- Handlers can return `ToolResult(content=..., isError=True)` or a mapping with `{"isError": True, "content": [...]}`.
- In `none` mode, the frame carries `"is_error": True`.
- In `end-to-end` mode, `"is_error": True` is authenticated within the HPKE envelope associated data (`associated_data` / `reply_header`), ensuring tampering fails AEAD decryption.
- The outcome is traced as `outcome="tool_error"`.

---

## 4. Testing & Validation

### 4.1. Local Unit Tests
Run within the repository `.venv` (Python 3.12):
```bash
.venv/bin/python -m pytest -v
```
Ensure `gateway_client.__file__` resolves to the local checkout (`sys.path[0]` precedence).

### 4.2. Real-Gateway End-to-End Suite
`tests/test_gateway_e2e.py` validates the client against a live `mcp-gateway` instance and PostgreSQL database:
```bash
createdb gwc_e2e_test
MCP_GATEWAY_DIR=/path/to/mcp-gateway TEST_DATABASE_URL=postgresql://localhost:5432/gwc_e2e_test .venv/bin/python -m pytest tests/test_gateway_e2e.py -v
dropdb gwc_e2e_test
```
Driver constraints (`tests/gateway_e2e_driver.py`):
- `SERVICE` WRN name must satisfy `[a-z][a-z0-9_]{1,61}[a-z0-9]` (e.g. `gwc_e2e`).
- User access grant must target the personal container `wrn:access:personal/<id>`.

---

## 5. Releases & Metadata Parity

- Releases follow Semantic Versioning (`X.Y.Z`).
- **Tag invariant**: Every git tag `vX.Y.Z` on origin must point to a commit whose `pyproject.toml` `version` and `gateway_client.__version__` match `X.Y.Z`.
- Validate parity across all tags:
  ```bash
  for t in $(git tag -l 'v*'); do git show "$t:pyproject.toml" | grep -q "version = \"${t#v}\"" || echo "Mismatch on $t"; done
  ```
- Always update `CHANGELOG.md` with release notes before tagging.
