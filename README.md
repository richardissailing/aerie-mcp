# falcon-fleet-mcp

A serverless MCP server that gives MCP clients (Claude Code, Claude Desktop, internal agents)
access to **every CrowdStrike Falcon tenant in the enterprise** through one endpoint. It
handles separate tenants in different Falcon clouds and Flight Control child CIDs. Users sign
in with their **IAM Identity Center** account, and Identity Center groups decide which tenants
each user can see and act on.

```
MCP client ──OAuth (PKCE)──► Cognito ──SAML──► IAM Identity Center
    │                                                     ▲
    │ Bearer token                                        │ group lookup (Identity Store API)
    ▼                                                     │
Lambda Function URL (ap-southeast-2) ─── falcon-fleet-mcp ┘
    │   ├─ DynamoDB: tenant registry + group→tenant grants
    │   └─ Secrets Manager: one Falcon API client per tenant / Flight Control parent
    ▼
Falcon APIs: tenant A (US-1) · child CIDs via parent (US-2) · tenant C (EU-1) …
```

## Tools

| Tool | Kind | Scope |
|---|---|---|
| `list_tenants` | read | tenants you can access, with your role in each |
| `fleet_overview` | read | per tenant: new alerts (all, and Critical/High) in the last N hours, hosts, contained hosts, hosts not seen for 7 days |
| `search_alerts` / `get_alerts` | read | searches all tenants at once with FQL / full records from one tenant |
| `search_hosts` / `get_host_details` | read | searches all tenants at once / one tenant |
| `hunt_indicator` | read | hosts in every tenant that have seen a sha256, md5, domain or IP, even with no alert |
| `search_vulnerabilities` | read | Spotlight, searches all tenants at once |
| `search_intel_actors`, `lookup_indicator` | read | Falcon Intelligence |
| `contain_hosts`, `lift_containment` | action | one tenant, needs the responder role and a reason, at most N hosts per call |
| `update_alerts` | action | one tenant, needs the responder role and a reason |

Read tools take an optional `tenants` list. Leave it out to query every tenant you can access.
Results are grouped by tenant, and if one tenant fails, the others still return (`tenants_failed`).
`search_alerts` and `search_hosts` take an `offset` for paging; it applies to each tenant, so compare
it with each tenant's `total`.

Action tools are only registered when `actions_enabled = true`. A call then also needs the
**responder** role for that tenant **and** `allow_actions = true` on the tenant. Every tool call
writes a JSON audit line (user, tenants, tool, filter, reason, outcome) to CloudWatch.

## Access model

- `access_grants` maps Identity Center **group display names** to tenants (`["*"]` = all) and a role
  (`reader` | `responder`). Where a user's groups give different roles for a tenant, the highest one applies.
- Groups are looked up from the Identity Store and cached for 5 minutes. Removing someone from a
  group in Identity Center takes effect within 5 minutes, even though their token is still valid.
- A user whose groups grant no tenants gets HTTP 403.
- **Cutting someone off**: remove them from their groups in Identity Center (or delete the user). That
  takes effect within 5 minutes. Disabling the user only stops new sign-ins: their existing refresh token
  keeps working for up to `refresh_token_hours` while their groups still grant access. To also end the
  session at once, run
  `aws cognito-idp admin-user-global-sign-out --user-pool-id <pool> --username IdentityCenter_<email>`.
- If the registry or Identity Store can't be read, requests get HTTP 503. The server refuses
  access rather than falling back to a cached policy, so revocations always take effect.
- If a user asks for a tenant they can't access, the server says "not found or not permitted", so
  it doesn't reveal whether that tenant exists.

## Deploy

Prerequisites: `uv`, Terraform ≥ 1.9, AWS credentials for the target account, and admin access to IAM Identity Center.

### 1. Test and build

```bash
uv sync
uv run pytest                      # Python tests (AWS calls run against moto)
(cd terraform && terraform init && terraform test)   # applies the stack to a mocked AWS provider
./scripts/build_lambda.sh          # -> build/lambda.zip (python3.13, arm64)
```

### 2. First apply (creates Cognito, Lambda, secrets and the registry; no SAML yet)

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars   # edit tenants, grants, identity store id
terraform init
terraform apply
```

### 3. Connect IAM Identity Center

In the Identity Center console, go to **Applications → Add application → I have an application
I want to set up → SAML 2.0**:

- **Application ACS URL** and **SAML audience**: copy from `terraform output identity_center_app_settings`.
- **Attribute mappings**: `Subject` → `${user:email}` (format `emailAddress`), and `email` → `${user:email}`.
  If you set `user_lookup_attribute = "userName"`, map `Subject` to the Identity Center username instead.
- **Assign** every group named in `access_grants` to the application.
- Copy the application's **IAM Identity Center SAML metadata file** URL into
  `identity_center_saml_metadata_url`, then run `terraform apply` again.

If Identity Center is in a different account (management or delegated admin), apply
`terraform/modules/identity-center-reader` in that account with the stack's `lambda_role_arn`
output. Then set `identity_store_role_arn` to the role it creates and apply again.

### 4. Load the Falcon API credentials

In each Falcon console, go to **Support → API Clients and Keys** and create a client with these scopes:

| Scope | Needed for |
|---|---|
| Alerts: Read (Write for `update_alerts`) | alerts |
| Hosts: Read (Write for containment) | hosts, containment |
| Vulnerabilities: Read | Spotlight |
| IOC Management: Read | `hunt_indicator` |
| Actors / Indicators (Falcon Intelligence): Read | intel tools |

For Flight Control, create the client in the **parent** CID. Then store each credential:
`terraform output load_secret_commands` prints one command per credential. Write
`{"client_id": "...", "client_secret": "..."}` to the `falcon-<name>.json` file it names (after
`umask 077`, so only you can read it) and run the command; it reads the file and then deletes it, which keeps the secret out of shell history and Terraform state.

A tenant's `base_url` must be a Falcon cloud name (`us1`, `us2`, `us3`, `eu1`, `usgov1`, `usgov2`) or an
`https://api…crowdstrike.com` URL. Terraform and the server both refuse anything else, because
FalconPy would treat an unknown name as a hostname and send the API secret to it.

### 5. Connect a client

```bash
terraform output -raw claude_code_command
# claude mcp add --transport http --client-id <id> --callback-port 33418 falcon https://<url>/mcp
```

In Claude Code, run `/mcp` and sign in through the browser. Clients that support dynamic client
registration also work without `--client-id`, but they must use a redirect URI listed in
`oauth_redirect_uris`, because Cognito only accepts exact matches.

## Adding a tenant

1. Add it to `tenants` (and `falcon_credentials` if it needs a new API client). For a Flight
   Control child, reuse the parent's credential and set `member_cid`.
2. Grant it to groups in `access_grants`.
3. Run `terraform apply`, then load the secret if it's new.

The code doesn't need to be redeployed. Running Lambdas pick up the registry change within 5 minutes.

### Onboarding a Flight Control parent's children

Give the parent API client the **Flight Control: Read** scope as well, then let the discovery
tool generate the `tenants` entries:

```bash
uv run python -m falcon_fleet_mcp.discover \
  --credential acme-parent --base-url us2 \
  --secret-id falcon-fleet-mcp/falcon/acme-parent \
  --prefix acme- --tfvars terraform/terraform.tfvars \
  --grant Acme-SOC:reader --grant Acme-IR:responder
```

- It lists every child of the parent and prints the `tenants` entries, plus optional
  `access_grants` lines, to stdout for you to review and paste in. It doesn't write anything.
- Children already in `--tfvars` (matched by `member_cid`) are skipped, and generated ids won't
  clash with existing tenant keys.
- `allow_actions` defaults to `false`. Pass `--allow-actions` to turn it on for every new entry.
- With `--tfvars`, it also warns about entries that use this parent's credential but whose CID is
  no longer one of its children (a removed or migrated child). Remove those yourself.
- Credentials come from `--secret-id` (Secrets Manager in `ap-southeast-2` by default), or from
  `FALCON_CLIENT_ID` / `FALCON_CLIENT_SECRET` if you're onboarding before the secret is stored.

Then run `terraform apply`. The children share the parent's secret, so there's no new secret to load.

## How the OAuth part works

Cognito is the token issuer, but MCP clients need a few things Cognito doesn't offer, so the
server provides a thin authorization-server layer in front of it (`src/falcon_fleet_mcp/auth.py`):

- RFC 9728 / RFC 8414 discovery documents that advertise PKCE S256 support
- `/register`, which answers dynamic registration with the single pre-registered public client
  (only for the allowed redirect URIs)
- `/authorize`, which sends the user straight to Identity Center (`identity_provider=IdentityCenter`)
- `/token`, which passes requests through to Cognito with the RFC 8707 `resource` parameter removed

Access tokens are checked against the Cognito JWKS: issuer, expiry, `token_use=access`, and an allowed `client_id`.

## Operational notes

- **Alarms**: set `alarm_email` to get emailed when calls are denied (`alarm_denied_threshold` in
  5 minutes, default 10), when any action runs (`alarm_on_actions`), or when the Lambda errors.
  The `DeniedCalls` and `ActionsExecuted` metrics are always published under `FalconFleetMcp/<name>`.
  Audit lines are bare JSON, so you can query them in Logs Insights: `filter ispresent(audit) | stats count() by user, outcome`.

- **Region**: everything deploys to `ap-southeast-2` (Sydney). Falcon API calls still go to each
  tenant's own Falcon cloud (US-1, US-2, EU-1, …).
- **Time budget**: a request that queries many tenants stops at `FANOUT_DEADLINE_SECONDS` (the Lambda
  timeout minus 10s). Tenants it didn't reach are reported in `tenants_failed` instead of the whole call timing out.
- **Rate limits**: Falcon rate limits apply per CID. `FANOUT_CONCURRENCY` (default 8) and the Lambda's
  reserved concurrency (default 20) cap how many requests hit Falcon at once. A rate-limited call is
  retried once if the limit resets within 2 seconds; otherwise that tenant reports the 429.
- **Reserved concurrency**: new AWS accounts often have a concurrency quota of 10, and Lambda refuses a
  reservation that leaves fewer than 10 unreserved. If the first apply fails on
  `ReservedConcurrentExecutions`, set `lambda_reserved_concurrency = -1` or request a quota increase.
- **Destroying**: the Cognito user pool has deletion protection. Turn it off in the console (or in
  `cognito.tf`) before `terraform destroy`.
- **Edge protection**: Lambda Function URLs can't have AWS WAF attached directly. For WAF, IP
  allow-listing or a custom domain, put CloudFront (with WAF) in front of the Function URL and
  set `public_base_url`.
- **Local development**:
  `AUTH_DISABLED=true DEV_GROUPS=soc-analysts REGISTRY_FILE=registry.json uv run uvicorn falcon_fleet_mcp.app:app`.
  `AUTH_DISABLED` is refused when running inside Lambda.
