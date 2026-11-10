# porte-rs — Configuration

Every field of `porte::Config`, the environment variable `Config::from_vars` reads it from,
and the traps. porte reads no variable on its own: the app calls `Config::from_vars` or fills
the struct.

## Variables

| Variable | Field | Required | Default | What it does |
|---|---|---|---|---|
| `OIDC_ISSUER` | `issuer` | no | — | Issuer URL. **Its presence is what enables OIDC** |
| `OIDC_CLIENT_ID` | `client_id` | with issuer | — | This app's client id at Registre |
| `OIDC_CLIENT_SECRET` | `client_secret` | with issuer | — | Its secret |
| `OIDC_REDIRECT_URL` | `redirect_url` | with issuer | — | Must match the redirect URI registered at Registre |
| `OIDC_SUCCESS_URL` | `success_url` | with issuer | — | Where the browser lands after sign-in |
| `OIDC_APP_NAME` | `app_name` | no | derived | The name on the CLI code page |
| `OIDC_LOGO_URL` | `logo_url` | no | derived | The logo on that page |
| `OIDC_CLAIMS_SCOPE` | `claims_scope` | no | — | The scope carrying `roles`. **Its presence enables roles** |
| `OIDC_MACHINE_AUDIENCE` | `machine_audience` | no | — | Audience a bearer JWT must carry. Set it to this app's client id |
| `OIDC_SCOPE_PREFIX` | `scope_prefix` | no | — | Gates bearer JWTs on `<prefix>.read` and `<prefix>.write`. Needs `OIDC_MACHINE_AUDIENCE` |
| `OIDC_CLI_AUDIENCE` | `cli_audience` | no | — | Mounts the device exchange. Set it to the CLI's client id, `facile-cli` |
| `SSO_ONLY` | `sso_only` | no | `false` | Reported by `GET /auth/config` |
| `PORTE_TOKEN_KEY` | (`pg::TokenSealer::parse`) | no | — | Seals stored OIDC tokens. Comma-separated 32-byte secrets, newest first, hex or base64 |

## Fields with no variable

| Field | Default | What it does |
|---|---|---|
| `failure_url` | `/login` on the success URL's origin | Where a failed browser login lands, with `error=<reason>` |
| `trust_email_without_verified_claim` | `false` | Lets a token with no `email_verified` claim match an account by address. Never overrides an explicit `false` |
| `extra_scopes`, `extra_claims` | empty | Scopes to request on top of the four, and claims to copy raw into `Claims::extra` |
| `session_ttl` | 30 days | Absolute session lifetime. Zero means the default |
| `session_idle_ttl` | `None`, 7 days | Idle window of a browser session. `Some(Duration::ZERO)` disables it |
| `claims_ttl` | 5 minutes | How long a cached roles claim is trusted |
| `login_code_ttl` | 60 seconds | Window for a CLI to redeem its code |
| `accept_legacy_cookie` | `false` | Also read the bare `session` cookie over https, for one migration |

## Traps

- **The cookie name follows the scheme.** Over https (`redirect_url` or `success_url` is
  https, the connection is TLS, or `X-Forwarded-Proto: https`) the cookie is
  `__Host-session` and the bare name is not read. A dev server on plain http uses `session`.
- **`Secure` only goes up.** A proxy that stops sending `X-Forwarded-Proto` cannot downgrade
  an app whose configured URLs are https.
- **The idle window applies to cookies only.** A bearer is a CLI or an API token, idle by
  design. A named token (`label` non-empty) never expires.
- **`PORTE_TOKEN_KEY` is fail-closed.** A sealed value no configured key opens reads as an
  empty token: the user signs in again, nothing panics. Keep the old secret second in the list
  until `Store::reseal_identities` has run.
- **`Manager::new` resolves zero durations once.** Build exactly one manager and pass it to
  every kit; a second manager over the same table would keep its own clock and cookie verdict.
