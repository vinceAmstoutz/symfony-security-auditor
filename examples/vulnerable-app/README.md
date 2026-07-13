# vulnerable-app

> [!CAUTION]
>
> **This application is intentionally vulnerable.** It exists to demonstrate
> `vinceamstoutz/symfony-security-auditor` against realistic-looking flaws. **Do
> not deploy it. Do not import any of its source files into a real project.**

A tiny Symfony 7 skeleton with deliberate flaws spanning classic controller bugs
and the newer attack surfaces the auditor learned to recognize (file uploads,
API Platform resources, Messenger webhook handlers, Twig extensions, and UX Live
Components). Run the auditor against it and observe the report. The
[`ground-truth.json`](ground-truth.json) manifest lists the expected findings,
one per row below, and `bin/castor eval` scores the auditor's detection against
it.

## Embedded flaws

| Where                                                       | Flaw                                                                                                   | OWASP                         |
| ----------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ | ----------------------------- |
| `src/Controller/UserController.php::deleteAction()`         | Missing `#[IsGranted]` / no `denyAccessUnlessGranted()` on a `DELETE` route.                           | A01 — Broken Access Control   |
| `src/Controller/UserController.php::showAction()`           | Direct object reference (`$id` from URL → `find()`) with no ownership check.                           | A01 — Broken Access Control   |
| `src/Controller/SearchController.php::queryAction()`        | Raw `$request->get('q')` concatenated into a DQL/SQL string.                                           | A03 — Injection               |
| `src/Entity/User.php::fromRequest()`                        | Mass-assigning every request field, including `isAdmin`, into the entity.                              | A04 — Insecure Design         |
| `src/Controller/AvatarUploadController.php::uploadAction()` | Client filename trusted for the extension check and destination path — upload lands under the docroot. | A04 — Insecure Design         |
| `src/Api/Invoice.php`                                       | API Platform resource with no `security` and every property serialized, including `costPrice`.         | A01 — Broken Access Control   |
| `src/Messenger/GitHubWebhookHandler.php`                    | Webhook handler acts on the payload with no HMAC signature check or replay de-duplication.             | A08 — Data Integrity Failures |
| `src/Twig/MarkupExtension.php`                              | Filter declared `is_safe => ['html']` echoes caller input verbatim, disabling autoescaping.            | A03 — Injection (XSS)         |
| `src/Twig/Components/UserCard.php::promote()`               | `#[LiveAction]` promotes to admin with no `#[IsGranted]` and trusts a client-writable `LiveProp`.      | A01 — Broken Access Control   |

## Running the auditor against it

```bash
cd examples/vulnerable-app
composer install
export ANTHROPIC_API_KEY=…             # or configure another platform
bin/console audit:run
```

Expected outcome:

- Exit code **1** (risk level `CRITICAL` once the controller findings are
  validated).
- Report lists ≈ 9 findings, one per row of the table above. Severity and
  wording vary by model.

To try a different provider, edit
[`config/packages/ai.yaml`](config/packages/ai.yaml).

## What this app does **not** demonstrate

It is a toy. There is no database, no real router beyond what's needed to make
the controllers look plausible, and no tests. The flaws are kept inline and
obvious so that a human can verify the auditor's output by eye. For real usage
patterns, see the [`configs/`](../configs/) recipes.
