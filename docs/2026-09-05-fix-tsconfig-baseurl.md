# Fix: `tsc --noEmit` broken by TypeScript 7 removing `baseUrl`

Status: OPEN (2026-09-05). Severity: medium (no type-checking has run since the upgrade).

## What is wrong

`waf-dashboard/package-lock.json` resolves `typescript` to 7.0.2 (pulled in
by commit f17945f "chore(deps): upgrade astro and integrations").
TypeScript 7 removed the `baseUrl` compiler option. `waf-dashboard/tsconfig.json`
still sets it:

```json
{
  "extends": "astro/tsconfigs/strict",
  "compilerOptions": {
    "baseUrl": ".",
    "paths": { "@/*": ["./src/*"] },
    "jsx": "react-jsx",
    "jsxImportSource": "react"
  }
}
```

Result:

```
$ bunx tsc --noEmit
tsconfig.json(4,5): error TS5102: Option 'baseUrl' has been removed. Please remove it from your configuration.
  Use '"paths": {"*": ["./*"]}' instead.
```

The documented type-check command in both AGENTS.md files therefore exits
non-zero on line 1 and checks nothing. Vitest still passes because
`vitest.config.ts` defines its own `@` alias, and `astro build` resolves
`paths` through Vite, so the breakage is invisible unless someone runs `tsc`.
CI (`.github/workflows/build.yml`, job `test-frontend`) only runs `vitest`,
so CI never ran `tsc` either.

## Fix plan

1. Remove `baseUrl`. `paths` entries are already relative to the tsconfig
   directory, so nothing else changes:

   ```json
   {
     "extends": "astro/tsconfigs/strict",
     "compilerOptions": {
       "paths": { "@/*": ["./src/*"] },
       "jsx": "react-jsx",
       "jsxImportSource": "react"
     }
   }
   ```

2. Run the check and fix whatever it surfaces. Type errors may have
   accumulated while the check was dead:

   ```bash
   cd ~/infra/ergo/caddy-compose/waf-dashboard
   bunx tsc --noEmit
   ```

   Treat each error on its merits; do not add `// @ts-expect-error` to get
   green.

3. Confirm the other two consumers of the alias still work:

   ```bash
   bunx vitest run          # 19 files / 359 tests at review time
   npm run build            # astro build; must resolve every "@/..." import
   ```

4. Put `tsc` in CI so this cannot silently break again. In
   `.github/workflows/build.yml`, job `test-frontend`, after `npm ci`:

   ```yaml
         - run: npx tsc --noEmit
           working-directory: waf-dashboard
         - run: npx vitest run
           working-directory: waf-dashboard
   ```

   `make check` already runs `tsc` locally per AGENTS.md; CI should match.

5. Commit:

   ```bash
   git add waf-dashboard/tsconfig.json .github/workflows/build.yml
   git commit -m "fix(dashboard): drop baseUrl for TypeScript 7, run tsc in CI"
   git push
   ```

   No deploy is needed unless step 2 changed runtime code. If it did, bump
   `WAFCTL_IMAGE` and deploy as usual.

## Verification

- `bunx tsc --noEmit` exits 0 with no output.
- `bunx vitest run` and `npm run build` succeed.
- The next GitHub Actions run on `main` shows the new `tsc` step green in
  `test-frontend`.

## Rollback

Pin `typescript` back to a 5.x release in `package.json`, `npm install`,
commit the lockfile. Only do this if step 2 uncovers more than a session's
worth of errors and a fix is needed immediately.
