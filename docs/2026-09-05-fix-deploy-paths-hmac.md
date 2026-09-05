# Fix: CSP and security-header deploy paths drop the challenge HMAC key

Status: OPEN (2026-09-05). Severity: low on its own (challenge is slated for
removal), but the duplication it exposes is worth removing regardless.

## What is wrong

`generatePolicyData` in `wafctl/deploy.go` is documented as "the single
source of truth for config generation". It is not. Two handlers re-implement
the pipeline inline and skip the last step:

| Handler | File | Injects `challenge_config`? |
|---|---|---|
| `handleDeploy` (`POST /api/deploy`, `POST /api/config/deploy`) | `handlers_config.go` via `generatePolicyData` | yes |
| `deployAll` (background: blocklist refresh, expiry cleanup, auto-escalation) | `deploy.go` via `generatePolicyData` | yes |
| `generateOnBoot` | `deploy.go` via `generatePolicyData` | yes |
| `handleDeployCSP` (`POST /api/csp/deploy`) | `csp.go:468` inline | **no** |
| `handleDeploySecurityHeaders` (`POST /api/security-headers/deploy`) | `security_headers.go:435` inline | **no** |

`rg -n 'ChallengeConfig\s*=' wafctl/*.go` confirms `deploy.go:97` is the only
injection site.

Effect: with at least one enabled `challenge` rule, a deploy from the CSP or
Security Headers dashboard pages writes `policy-rules.json` without
`challenge_config`. The plugin's `provisionChallengeKey`
(`caddy-policy-engine/challenge.go`) then logs
`using ephemeral challenge HMAC key (cookies invalidated on restart)` and
generates a random key. Every outstanding challenge cookie fails validation;
every visitor re-solves the proof of work. The next `/api/deploy` restores the
persisted key and invalidates the ephemeral cookies in turn.

The two inline copies also drift on their own: they build the response and
skip the `policyCount` log line, and they would miss any future step added to
`generatePolicyData`.

## Fix plan

Follow TDD here: the bug has a clean red test.

### 1. Red test

Add to `wafctl/deploy_test.go`, using the store setup from
`TestDeployEndpointNoReload` (add `strings` to the file's imports):

```go
func TestCSPAndHeaderDeployKeepChallengeConfig(t *testing.T) {
	wafDir := t.TempDir()
	caddyfilePath := filepath.Join(t.TempDir(), "Caddyfile")
	os.WriteFile(caddyfilePath, []byte("localhost:80\n"), 0644)

	key := strings.Repeat("ab", 32) // 64 hex chars, decodes to 32 bytes
	deployCfg := DeployConfig{
		WafDir:           wafDir,
		CaddyfilePath:    caddyfilePath,
		PolicyRulesFile:  filepath.Join(wafDir, "policy-rules.json"),
		ChallengeHMACKey: key,
	}

	es := NewExclusionStore(filepath.Join(t.TempDir(), "exclusions.json"))
	if _, err := es.Create(RuleExclusion{
		Name: "pow", Type: "challenge", Enabled: true,
		Conditions: []Condition{{Field: "path", Operator: "begins_with", Value: "/admin"}},
	}); err != nil {
		t.Fatal(err)
	}
	cs := NewConfigStore(filepath.Join(t.TempDir(), "config.json"))
	ls := NewManagedListStore(filepath.Join(t.TempDir(), "lists.json"), t.TempDir())
	cspStore := NewCSPStore(filepath.Join(t.TempDir(), "csp.json"))
	secStore := NewSecurityHeaderStore(filepath.Join(t.TempDir(), "sec.json"))
	corsStore := NewCORSStore(filepath.Join(t.TempDir(), "cors.json"))
	ds := NewDefaultRuleStore(filepath.Join(t.TempDir(), "defaults.json"), filepath.Join(t.TempDir(), "overrides.json"))

	routes := map[string]http.HandlerFunc{
		"/api/csp/deploy":              handleDeployCSP(cspStore, secStore, corsStore, cs, es, ls, ds, deployCfg),
		"/api/security-headers/deploy": handleDeploySecurityHeaders(secStore, cspStore, corsStore, cs, es, ls, ds, deployCfg),
		"/api/deploy":                  handleDeploy(cs, es, ls, cspStore, secStore, corsStore, ds, deployCfg),
	}
	for path, h := range routes {
		t.Run(path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest("POST", path, nil))
			if rec.Code != 200 {
				t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
			}
			data, err := os.ReadFile(deployCfg.PolicyRulesFile)
			if err != nil {
				t.Fatal(err)
			}
			var file PolicyRulesFile
			if err := json.Unmarshal(data, &file); err != nil {
				t.Fatal(err)
			}
			if file.ChallengeConfig == nil || file.ChallengeConfig.HMACKey != key {
				t.Fatalf("challenge_config missing or wrong after %s: %+v", path, file.ChallengeConfig)
			}
		})
	}
}
```

Run it and confirm the two subtests for `/api/csp/deploy` and
`/api/security-headers/deploy` fail while `/api/deploy` passes:

```bash
cd ~/infra/ergo/caddy-compose/wafctl
go test -count=1 -timeout 60s -run TestCSPAndHeaderDeployKeepChallengeConfig ./...
```

### 2. One write path

Add to `wafctl/deploy.go`:

```go
// writePolicyRules regenerates policy-rules.json from all stores under
// deployMu. Every deploy entry point (HTTP or background) goes through here.
func writePolicyRules(cs *ConfigStore, es *ExclusionStore, ls *ManagedListStore, cspStore *CSPStore, secStore *SecurityHeaderStore, corsStore *CORSStore, ds *DefaultRuleStore, deployCfg DeployConfig) (int, error) {
	deployMu.Lock()
	defer deployMu.Unlock()

	policyData, policyCount, err := generatePolicyData(cs, es, ls, cspStore, secStore, corsStore, ds, deployCfg)
	if err != nil {
		return 0, err
	}
	if err := atomicWriteFile(deployCfg.PolicyRulesFile, policyData, 0644); err != nil {
		return 0, fmt.Errorf("writing policy rules file: %w", err)
	}
	log.Printf("[deploy] wrote policy rules (%d rules) -> %s", policyCount, deployCfg.PolicyRulesFile)
	return policyCount, nil
}
```

Then:

- `deployAll` becomes `_, err := writePolicyRules(...); return err`.
- `handleDeploy` calls `writePolicyRules` and maps the error to the existing
  500 response. Keep the response body unchanged (`status: deployed`).
- `handleDeployCSP` and `handleDeploySecurityHeaders`: delete the inline
  pipeline; call `writePolicyRules` and keep their existing response types so
  the dashboard's `csp.ts` and `security-headers.ts` modules do not change.

Error-wrapping note: `generatePolicyData` already returns wrapped errors
(`generating policy rules: ...`, `applying default rule overrides: ...`), so
the more specific 500 messages the inline copies produced collapse to
`failed to generate policy rules` with the wrapped detail. That is fine; the
detail string still names the failing step.

### 3. Fix the existing CSP test

`csp_test.go:542` registers `handleDeployCSP(store, nil, nil, nil, nil, nil, nil, deployCfg)`.
With the shared pipeline, nil stores dereference (`es.EnabledExclusions()`).
Replace the nils with real temp stores using the same constructors as the
red test. The behaviour under test (CSP config lands in `policy-rules.json`)
is unchanged.

### 4. Green

```bash
gofmt -l . && go vet ./... && go test -count=1 -timeout 60s ./...
```

All three subtests pass. Also run
`go test -count=1 -run 'TestDeploy|TestCSP|TestSecurityHeader' ./...` to
cover the handlers whose bodies changed.

### 5. Optional: collapse the routes

Four deploy routes now do the same thing. If you take this further:

- keep `POST /api/deploy`, delete `POST /api/config/deploy`,
  `POST /api/csp/deploy`, `POST /api/security-headers/deploy` from `main.go`;
- point `deployCSP` in `waf-dashboard/src/lib/api/csp.ts` and the equivalent
  in `security-headers.ts` at `/api/deploy`, and adjust their response types
  to `DeployResponse`;
- update the `test/e2e` cases that hit the removed routes
  (`rg -n 'csp/deploy|security-headers/deploy|config/deploy' test/e2e`).

This is a good candidate for the edgectl rename session rather than now.

### 6. Ship

Bump `WAFCTL_IMAGE` (see `2026-09-05-fix-version-tag-sync.md`), commit
`fix(wafctl): route every deploy through one policy-rules writer`, push,
`make restart` after CI publishes.

## Verification on the router

Only meaningful while a `challenge` rule exists.

```bash
ssh router 'docker exec wafctl wget -qO- --post-data= http://localhost:8080/api/csp/deploy'
ssh router 'jq -c .challenge_config /var/lib/caddy/waf/policy-rules.json'
# expect {"hmac_key":"..."} (64 hex chars), never null
ssh router 'docker logs caddy --since 1m 2>&1 | grep -i "challenge HMAC"'
# expect "challenge HMAC key loaded from config", never "ephemeral"
```

Do not paste the key value into chat or a commit.

## Rollback

Redeploy the previous `wafctl` tag. No data format changed.
