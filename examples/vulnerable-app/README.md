# vulnerable-app

> [!CAUTION]
>
> **This application is intentionally vulnerable.** It exists to demonstrate `vinceamstoutz/symfony-security-auditor` against realistic-looking flaws. **Do not deploy it. Do not import any of its source files into a real project.**

A tiny Symfony 7 skeleton with deliberate flaws across three OWASP categories. Run the auditor against it and observe the report.

## Embedded flaws

| Where | Flaw | OWASP |
| --- | --- | --- |
| `src/Controller/UserController.php::deleteAction()` | Missing `#[IsGranted]` / no `denyAccessUnlessGranted()` on a `DELETE` route. | A01 — Broken Access Control |
| `src/Controller/UserController.php::showAction()` | Direct object reference (`$id` from URL → `find()`) with no ownership check. | A01 — Broken Access Control |
| `src/Controller/UserController.php::listAction()` | Bare indexed-array `JsonResponse` on a `GET` route (XSSI "JSON Hijacking"). | A01 — Broken Access Control |
| `src/Controller/SearchController.php::queryAction()` | Raw `$request->get('q')` concatenated into a DQL/SQL string. | A03 — Injection |
| `src/Entity/User.php::fromRequest()` | Mass-assigning every request field, including `isAdmin`, into the entity. | A04 — Insecure Design |

## Running the auditor against it

This directory has no `bin/console` and no kernel: it is a source tree to audit, not an application to boot. Audit it with the [standalone binary](../../README.md#standalone-tool-binary), after the one-time `init` that picks a provider and stores its API key:

```bash
symfony-security-auditor init
symfony-security-auditor audit examples/vulnerable-app
```

From a Symfony project that has the bundle installed, `bin/console audit:run path/to/examples/vulnerable-app` audits it the same way.

Expected outcome:

- Exit code **1** (risk level `CRITICAL` once the controller findings are validated).
- Report lists ≈ 5 findings, one per row of the table above. Severity and wording vary by model.

To try a different provider, run `symfony-security-auditor init` again, or edit the `platform:` block of your [standalone configuration](../../docs/configuration.md#standalone-configuration).

## What this app does **not** demonstrate

It is a toy. There is no database, no real router beyond what's needed to make the controllers look plausible, and no tests. The flaws are kept inline and obvious so that a human can verify the auditor's output by eye. For real usage patterns, see the [`configs/`](../configs/) recipes.
