# Changelog

All notable changes to `vinceamstoutz/symfony-security-auditor` are documented in this file, release by release: one line per change, grouped by kind of change, written for the people who run the auditor.

This project adheres to [Semantic Versioning 2.0.0](https://semver.org). See [`docs/versioning.md`](docs/versioning.md) for the backward compatibility policy — what is public API, what is internal, and how deprecations are handled. The format of this file is described in [`.claude/rules/changelog.md`](.claude/rules/changelog.md) and enforced by `.github/scripts/check-changelog.sh`.

## [Unreleased]

### New Features ✨

- Every push to `1.x` publishes a `snapshot` pre-release, versioned like `1.21.0+14.g4531440`, so a fix can be tried before it ships: `self-update --snapshot`, or the installers with `SSA_VERSION=snapshot`; a plain `self-update` takes a snapshot back to the latest release ([#631](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/631))
- `audit.tools_scope` (`audited` by default, or `scanned`) sets which files the `read_file`, `grep` and `list_files` tools may open: `scanned` lets a `--since` or `--path` run follow a changed controller into unchanged files, at the price of sending them to the provider on request; a standalone project file may not set it ([#490](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/490), [#550](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/550))
- With `audit.tools_scope: scanned`, the reviewer judges a finding the attacker recorded in a file read through the tools against that file's code, not an empty file ([#521](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/521))
- `xss` is now a finding type of its own (CWE-79, OWASP A05:2025), replacing `twig_injection` and `sensitive_data_exposure` for XSS; filters and baseline entries naming either keep matching it ([#467](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/467), [#544](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/544), [#573](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/573), [#613](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/613))
- `audit.report_path_prefix` puts the folder a project lives in before the paths of the SARIF and `github` formats, so alerts of a project in a sub-folder land on the right file; JSON and baseline paths stay project-relative ([#455](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/455))
- `audit.min_score`, `audit.fail_on_incomplete`, `audit.format` and `audit.output` set the gate and report options in YAML; a flag always wins, `--no-fail-on-incomplete` and `--no-output` switch a configured value off for one run, and a standalone project file may not set `audit.output` ([#412](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/412), [#553](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/553))
- `audit:run --dry-run` never writes its zero-finding estimate to a configured `audit.output`, so it cannot replace the last real report ([#412](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/412))
- An empty `audit.output`, or an `%env()%` placeholder that resolves to nothing, prints the report as `null` does instead of stopping the run ([#586](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/586))
- The GitHub Action's `fail-on-incomplete` input now defaults to empty and leaves the run to `audit.fail_on_incomplete`, an empty `output` input still prints the report to the job log, an empty `min-score` leaves the run to `audit.min_score`, and a command older than 1.22 is passed neither new flag ([#574](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/574))
- The standalone binary reads your `config.yaml`, then the `.symfony-security-auditor.yaml` of the working directory, then the one of the project `audit <project-path>` names, then the flags ([#411](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/411), [#538](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/538), [#553](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/553), [#629](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/629))
- An audited project's `.symfony-security-auditor.yaml` the standalone binary cannot accept is skipped with a warning, naming the reason, instead of stopping the run; the header names the keys such a file may not set ([#553](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/553), [#597](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/597))
- A project `.symfony-security-auditor.yaml` over 512 KiB or nested more than 32 levels deep, or naming a baseline that is not a regular file inside the project of at most 1 MiB, is skipped with the reason instead of crashing the binary ([#579](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/579), [#602](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/602), [#629](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/629))
- The standalone binary has `audit:diff`, `audit:trend` and `audit:baseline`, which run without any configuration ([#451](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/451))
- `init` checks that Composer runs before it asks anything, and says whether Composer or PHP is missing and how to install it on your system; `doctor` reports the same reason; `--no-interaction` on an existing configuration without `--force` still declines the overwrite and exits `0` without checking Composer ([#476](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/476), [#583](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/583))
- A failed chunk names its cause on the progress line, for example `✗ chunk 6/12 failed (26s) — tool-call limit reached (audit.max_tool_iterations)` ([#409](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/409))
- `scan.include_tracked_ignored` (default `false`) audits files git tracks although a `.gitignore` pattern matches them ([#515](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/515), [#542](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/542))
- A custom scanner can take the `--path` values of a run by implementing `ScopedProjectFileScannerInterface`; one that does not keeps the files of its configured scope under the paths ([#540](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/540), [#635](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/635))
- `scan.include_dotfiles` (default `false`) audits dot files and dot directories under `scan.included_paths`, matched by name patterns such as `.*.php`; version-control directories (`.git`, `.svn`, `.hg`, `.bzr`, `CVS`, `_darcs`) stay out either way ([#572](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/572))
- The report's coverage lists, as `skipped` under the `scan` stage, every file the scan leaves out for exceeding `scan.max_file_size_kb` or being unreadable; it never trips `--fail-on-incomplete` ([#473](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/473), [#482](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/482), [#541](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/541))
- Two files whose names or contents read the same once their invalid UTF-8 bytes are repaired are reported `errored`, so the report is incomplete and `--fail-on-incomplete` exits `3` ([#482](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/482), [#582](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/582))
- The secret scrubber redacts more credential shapes: every literal argument of credential-named setters and config builders, `new PDO()` arguments, `$cfg['password'] =` offsets, YAML `|` and `>` block scalars, `<argument key>` XML parameters, cut-off PEM keys, unclosed quotes and `sk-` keys of any length ([#475](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/475), [#611](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/611))
- The secret scrubber also redacts LexikJWT `pass_phrase`, HttpClient `auth_bearer` and `auth_basic`, `Authorization` headers of any scheme, credential query parameters such as `?token=`, and the credentials passed to `new Credentials()`, LDAP `bind()`, `ldap_bind()`, Redis `auth()`, `ftp_login()`, `imap_open()`, `new mysqli()` and Guzzle's `auth` ([#611](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/611))
- The decryption key of a Symfony secrets vault no longer reaches the provider; the file is still audited, with its key literals redacted ([#601](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/601))
- `privacy.offline_only` bypasses an environment proxy for loopback endpoints (`localhost`, `127.0.0.0/8`, `::1`) so prompts cannot leave the machine through it; an endpoint elsewhere on the private network still uses the proxy ([#489](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/489), [#545](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/545))

### Deprecations 💀

- A `scan.custom_risk_patterns` bucket that names no file type never matches a file and is deprecated since 1.22, to be refused in 2.0: `audit:run` prints a notice naming the bucket and the file types to key it by ([#594](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/594))

### Bugfixes 🐛

- A JSON answer that gives its only finding as a bare object instead of a one-element array reports that finding and caches its chunk, instead of losing it (`audit.structured_collection: false`, or a client that ignores the tools)
- `audit:run --dry-run` with an `audit.max_iterations` or `audit.max_tool_iterations` so large that its token estimate overflows prints the estimate held at the largest token count instead of stopping with an unexpected error
- `audit app/src` audits the project `app` narrowed to `src`, as `audit app --path src` does, instead of finding no file: a folder with no `composer.json` and nothing to scan is read as part of the Composer project it lies in, whose configuration applies, and a `--path` given from outside a project reaches it the same way ([#634](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/634))
- A pipeline stage or token estimator defined in an application's own autoconfigured `services.yaml` now joins the audit; an autoconfigured stage runs at priority `0`, before `IngestionStage`, unless it sets a lower one ([#565](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/565))
- An application whose `ai.yaml` configures several platforms is told so, with the platforms named and how to select one, instead of `No AI platform is configured` ([#595](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/595))
- `install.ps1` honors `SSA_INIT=1` and runs `init` right after installing; an `init` that fails only prints a warning and keeps the installed binary ([#562](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/562))
- The scrubber redacts a hard-coded fallback written after a code-shaped value under a credential key, such as `$password = getenv('X') ?: 'secret'`, and keeps the code around it ([#535](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/535))
- The scrubber redacts a password written alone as the user part of a URL (`redis://secret@host`, `sendgrid://KEY@default`, `…+api` mailer schemes); `https://deploy-bot@example.com` and `ssh://git@github.com` stay readable ([#516](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/516))
- Secret scrubbing no longer breaks the PHP and YAML the auditor parses next, so routes keep their access-control hints and `security.yaml` is still read; `secret: null` and `persist-credentials: false` no longer raise the `scrubbed_secret` marker ([#471](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/471), [#499](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/499))
- Secret scrubbing keeps the line numbers after a redaction, no longer flags a credential-free DSN such as `MAILER_DSN=null://null`, and no longer lets a `$`-prefixed secret through as an environment reference ([#464](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/464))
- An answer whose usage is missing or reports no prompt tokens is booked at its estimated input tokens instead of zero, so `audit.budget.*`, `audit.rate_limit.*` and the report totals see the spend (default AWS Bedrock route included) ([#514](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/514), [#531](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/531), [#556](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/556))
- Cached input is billed once, at the cache rate, for OpenAI, Gemini, DeepSeek and OpenAI-compatible gateways, so `estimated_cost_usd` and budgets no longer run up to 3x high; `audit.rate_limit.input_tokens_per_minute` still counts the whole prompt ([#456](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/456), [#589](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/589))
- Anthropic cache writes count against `audit.rate_limit.input_tokens_per_minute`, so a run with `cache_retention: short` stays under the configured cap instead of drawing HTTP 429s ([#589](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/589))
- Cache writes Anthropic keeps for an hour (`cache_retention: long`) are priced at twice the input rate, so the reported cost and `audit.budget.max_cost_usd` no longer run up to about 37% low ([#580](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/580))
- Gemini and Vertex AI thought tokens are billed as output, so cost reports and `audit.budget.*` no longer run low on a thinking model ([#491](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/491))
- A thinking model whose answer is cut off inside its reasoning is booked and answered as a `length` response instead of throwing, and a batch window no longer sends that request twice ([#492](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/492))
- Tool conversations with a thinking-enabled model send the model's own turn back whole, signed thinking block included, instead of failing with an HTTP 400 ([#485](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/485))
- An HTTP 403, 404 or 422 refused by an OpenAI-compatible gateway is no longer booked as spent, and the run goes on past it ([#549](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/549))
- A `429` saying the billing quota is exhausted stops the audit at once instead of retrying for three minutes; a rate limit that suggests a wait is still retried ([#486](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/486))
- A model answering with several tool calls in one turn no longer loses all but the first on Anthropic, Bedrock Claude, Gemini and Vertex ([#440](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/440))
- A chunk that explored up to `audit.max_tool_iterations` records what it holds and completes instead of failing on every run: the model is told its last round is the last ([#410](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/410))
- A model that reads past its last tool round gets one closing request to record what it holds instead of failing the chunk; a chunk ending at `audit.max_tool_iterations` with no finding, or a verdict reached there after reading files, stays out of the cache and triage memory, so the next run looks again ([#637](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/637), [#638](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/638))
- A chunk whose `record_vulnerability` call the tool refused and the model never repeated is reported incomplete and left out of the cache, instead of being cached as analyzed ([#474](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/474), [#627](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/627))
- A refused record call the model then makes in full is settled even when the retry re-words the title, so the chunk no longer reads incomplete and `--fail-on-incomplete` no longer exits `3` for it, and another finding of its file is never taken for that retry ([#496](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/496), [#627](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/627))
- `record_vulnerability` and `record_review` calls missing a required key get an error back so the model retries, instead of being acknowledged as recorded ([#431](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/431))
- A custom LLM client that ignores the tools no longer reports a clean run when its model answered findings: the answer is read as JSON, an unreadable one marks the chunk errored, and the run warns once, naming `audit.structured_collection: false` ([#600](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/600))
- A custom LLM client's token usage counts toward `audit.budget.max_tokens`, the report's token totals and its cost; `audit.budget.max_cost_usd` applies only to a model the pricing catalog prices, and the run warns once for any other ([#604](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/604))
- The DeepSeek bridge suggestion and the docs recommend `deepseek-flash` and `deepseek-v4-pro`, which the pricing catalog prices, instead of legacy ids it priced at $0 and a cost budget refused ([#581](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/581))
- A finding the model reported but the auditor could not read no longer turns its file into a clean one: the chunk is reported incomplete and left out of the cache, and over-long text, an inverted line range, a capitalised `type` or `severity` and a percentage `confidence` are repaired ([#425](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/425))
- A `confidence` on a zero-to-ten scale (`8`) is no longer read as a tiny percentage and filtered out: the entry is dropped, its chunk reported incomplete and asked again on the next run ([#495](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/495))
- A finding the reviewer never judged is reported as incomplete instead of counted as a rejection, so the attacker is not told to stop reporting it and it is reviewed again on the next run ([#435](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/435))
- A reviewer verdict of `"no"` or `"rejected"` no longer validates the finding, and an `adjusted_severity` or `corrected_type` in capitals is honoured ([#506](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/506))
- A reviewer failure that a later iteration recovers no longer leaves the report `complete: false` ([#559](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/559))
- One file the pre-scan flags on every line no longer stops the audit: each pattern lists its first 20 markers per file and counts the rest ([#472](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/472))
- A suggested fix or PoC cut off by the output limit is dropped, and the finding keeps its original `remediation` or `proof` ([#463](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/463))
- A budget or provider abort in the second half of a split chunk keeps the findings of the first half ([#466](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/466))
- With escalation on, a cheap-model finding the deep pass judged and dropped no longer comes back into the report, also when a budget cap or a provider failure stops the deep pass on a later file ([#423](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/423))
- Findings that collapse into one keep the most severe, a later verdict can no longer lower a reported severity, and a re-reported finding that widens over a validated neighbour absorbs it instead of inflating the risk score ([#421](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/421), [#497](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/497))
- A copy of a finding below the confidence floor no longer hides the confident copy of the same finding, which was then never reviewed ([#513](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/513))
- A finding is named by the project file it is about however the model spelled the path (absolute, `./`, backslashes), also when the model reported it while analyzing another file, so the reviewer sees its code and one weakness is one finding ([#422](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/422), [#481](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/481), [#569](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/569))
- A baseline written by 1.21.0 keeps accepting a finding whose file path the model spelled differently, and `audit:baseline` matches such an entry against a report written without that baseline ([#558](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/558), [#573](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/573), [#623](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/623))
- `audit:diff` and `audit:trend` no longer report a finding the baseline accepted, or a muted type, as fixed: it is listed as unverified ([#525](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/525), [#613](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/613))
- `audit:baseline --prune` keeps the accepted entries, with their reasons, of findings the report was written without; the JSON report gains the keys `suppressed_fingerprints` and `suppressed_baseline_fingerprints` ([#500](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/500), [#613](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/613))
- A baseline file escapes bidirectional overrides and other invisible characters in a finding's `title` and `file`, so a reviewed pull request cannot be spoofed ([#527](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/527))
- `audit:baseline` and `--generate-baseline` keep accented and non-Latin `reason`, `title` and `file` text as written instead of `\uXXXX` escapes ([#502](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/502))
- A baseline entry without a fingerprint stops a `--format=sarif` run before the first model call, as it does for every other format ([#501](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/501))
- A SARIF report marks as accepted only as many findings as the baseline accepts ([#436](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/436))
- A SARIF report written on Windows (`file:///C:/proj/src/A.php`) matches the project it describes, so `scan.import_sarif` imports its markers ([#448](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/448))
- `--format=github` no longer fails the whole report on a carriage return, an invisible character, then a line feed, and no longer leaves characters unescaped next to a combining mark ([#526](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/526))
- A scan that found no file is no longer presented as SAFE, grade A: every format reads `UNKNOWN (no file was analyzed)`, SARIF sets `executionSuccessful: false`, the JSON report gains `files_discovered`, and the GitHub Action's `highest-severity` is `UNKNOWN` ([#437](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/437), [#543](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/543), [#575](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/575))
- `--dry-run --since` on a diff with no auditable file no longer says the scan found no file to audit ([#478](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/478))
- `--dry-run` prices the project mapping and the system prompt every chunk carries, also with `--path`, so a route-heavy project is no longer underestimated about fivefold ([#461](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/461), [#480](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/480))
- `audit:run --min-score` still accepts a value outside 0 to 100 and now warns on stderr what it does: above 100 fails every run, below 0 never fails one ([#537](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/537))
- A `--path` spelled with `.`, `..` or an empty segment no longer hides the files the scan left out ([#479](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/479))
- `--path` scans the folders and files it names, whatever `scan.included_paths` lists: `--path apps/api` reaches a folder it leaves out, `--path src` audits all of `src` even when it lists a narrower folder, and `--path .` keeps it ([#411](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/411), [#540](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/540), [#635](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/635))
- Overlapping `scan.included_paths`, a folder listed inside another, no longer list a file twice ([#411](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/411))
- A project path that is not a directory, or an absolute `--path`, is refused with the reason (exit `1`) instead of ending as an empty scan; an absolute `--path` inside the project is made relative, also when a symbolic link spells it or the project differently (a shell's `$PWD` under macOS `/tmp`), one outside it is refused, and an empty scan says where it looked ([#411](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/411))
- `audit` no longer dies in a project directory, `project-path` or `--path` whose name is not valid UTF-8 ([#483](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/483), [#528](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/528))
- A file or file name that is not valid UTF-8 no longer aborts the audit: each invalid byte is written as the Latin-1 character of that byte, so names differing only in such bytes stay distinct, and a warning names the path, also under `--since` ([#462](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/462), [#582](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/582))
- `--path` no longer hides `security.yaml`, voters and forms from the Symfony mapping, so a protected route is not read as lacking a check, and `audit.since_closure: direct` stays within `--path` ([#452](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/452), [#540](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/540), [#571](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/571), [#585](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/585))
- `--since` on a repository git refuses (dubious ownership, unknown repository extension) reports git's own reason instead of blaming the ref or the project path ([#503](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/503))
- A file named `HEAD` or `<ref>...HEAD` in the audited repository no longer makes every `--since` run fail ([#518](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/518))
- `--since` audits a new file that was never `git add`ed, as documented ([#453](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/453))
- `--since` audits a file that replaced a committed symlink instead of leaving it out and reading SAFE ([#570](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/570))
- A Venice model that ends its turn with empty text no longer aborts the audit: the chunk keeps the findings already recorded and is reported incomplete ([#590](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/590))
- A provider's HTTP 408, 425, 429 or 5xx is retried with the usual back-off whatever its bridge made of the body, so a busy Ollama server or reverse proxy gets the retries `audit.retry.max_attempts` promises ([#621](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/621))
- An OpenAI `429` on the token limit is retried after the wait it asks for, not after the one-second request-window reset that aborted the audit after three attempts ([#592](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/592))
- A Gemini or Vertex AI answer that ends on an abnormal finish reason (`MALFORMED_FUNCTION_CALL`, `RECITATION`, `OTHER`, …) with no content is reported as an incomplete chunk and left out of the cache, instead of reading as a clean verdict ([#620](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/620))
- A directory the audit cannot read no longer aborts the scan: it is skipped with a `Skipped unreadable directory` warning ([#447](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/447))
- A named pipe or other non-regular file named like a source file in a scanned folder no longer hangs the audit: it is reported as an unreadable skipped file and never opened ([#578](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/578))
- `init` refuses a provider instance named by an `%env()%` placeholder (exit `2`) instead of writing a configuration the next run cannot select ([#427](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/427))
- A hyphenated `offline-only` or provider instance name in `config.yaml` is read the way the audit reads it, so `self-update` honours the offline guard and `auth:set` and `auth:status` find the credential variable ([#426](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/426))
- A `%` in the cache or working directory, or in a risk pattern, scrubbing pattern or skill instruction of the standalone user config, is no longer read as container syntax ([#420](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/420), [#532](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/532))
- `attacker_model`, `reviewer_model` and `audit.escalation.cheap_model` take a `%env()%` placeholder under a Symfony kernel, as `model` does ([#568](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/568))
- A model key set to a number or a switch stops with a configuration error that names the key instead of a raw `TypeError` ([#587](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/587))
- With `privacy.offline_only`, a standalone `--dry-run` whose endpoint comes from an unset `%env()%` variable is no longer refused as a hosted provider; a real run still stops on the unset variable ([#584](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/584))
- A `%env()%` placeholder on a number, a switch or a choice of the bundle configuration stops with a configuration error naming the key instead of a raw `TypeError` or `ValueError` ([#509](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/509), [#568](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/568))
- An explicit `null` on a nullable numeric key (`audit.budget.max_cost_usd: ~`, `audit.min_score`, …) is accepted, as the configuration reference and the JSON schema document ([#493](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/493))
- The configuration schema flags a misspelled vulnerability type or skill file type in the editor ([#566](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/566))
- `provider_json_mode: true` no longer sends Claude an empty JSON schema on the `anthropic` and `bedrock` platforms, which Bedrock's Mantle route refused; it is documented as sending `response_format: json_object` only to a model whose name contains `claude` ([#494](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/494), [#591](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/591))
- `access_control` rules are applied in the order Symfony applies them (the root block before `when@prod`, a public `route:` rule before a broader `path:` rule), so a public route is no longer shown as covered ([#511](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/511), [#529](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/529))
- An `access_control` path that is not a valid regular expression no longer aborts the prompt build ([#441](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/441))
- A route guarded only by `PUBLIC_ACCESS` or `IS_AUTHENTICATED_ANONYMOUSLY`, as an attribute, a `#[Security]` expression or a `denyAccessUnlessGranted()` call, is no longer counted as access-checked and gets `LACKS_ACCESS_CHECK` ([#507](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/507), [#530](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/530))
- A route the first matching `access_control` rule lets everyone through, such as a rule with only `requires_channel` or `ips`, is marked `LACKS_ACCESS_CHECK` instead of covered ([#615](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/615))
- The mapping reads the `access_control` rules and firewalls of every configuration file the production kernel loads (other package files, `when@prod` blocks, `imports:`, a monorepo application's own on a `--path` run), so a route they guard no longer reads as lacking a check; an unreadable security file is named in the attacker prompt ([#614](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/614))
- `audit.since_closure: direct` also pulls in the controllers that guard with a voter constant, such as `#[IsGranted(PostVoter::EDIT)]`, and `--show-scanned` and `--dry-run` list and price the controllers it adds to a `--since` run ([#612](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/612))
- Code slicing no longer hides string-built SQL passed to `->query(`, `->prepare(`, `->fetchAllAssociative(`, `->createNativeQuery(`, `->find(` and `->findOneBy(` from the attacker, multi-line calls included ([#442](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/442))
- A voter holding thousands of string literals, or fetching a constant array thousands of times, no longer slows the mapping, floods every prompt or exhausts a 128 MB process; each voter list is capped and ends with `… and N more` ([#468](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/468), [#523](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/523))
- A controller whose actions call each other, or stack many `#[IsGranted]` and `#[Route]` attributes, no longer multiplies its form bindings and guards into prompts of megabytes or an exhausted 128 MB process; the lists are capped ([#522](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/522), [#524](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/524))
- A `security.yaml` listing thousands of roles or firewalls no longer floods every attacker request: a route's `COVERED_BY` label lists at most 20 requirements and the firewall block at most 50 firewalls, each ending with `… and N more` ([#588](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/588))
- A `--baseline` or `scan.import_sarif` file over 32 MiB, such as a symlink to `/dev/zero`, stops the run with a clear error and exit `1` instead of exhausting memory ([#602](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/602))
- The MCP `audit` tool keeps the partial report, after the muted types and the baseline, of a run a budget cap or a provider failure stopped, as `audit:run` does ([#508](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/508))
- `audit --help` lists `github-comment` among the formats and no longer shows a `--format` default that `audit.format` replaces, and the standalone binary's help names the configuration files it reads ([#498](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/498), [#567](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/567))
- A failed `composer audit` is remembered for five minutes instead of being re-run by every `lookup_advisory` call, and a long-lived `mcp:serve` sees advisories disclosed after its first lookup: the in-memory snapshot expires after 24 hours ([#446](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/446), [#487](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/487))
- The advisory lookup no longer reads a hostile `composer.lock` whole, caches a `composer audit` output it cannot use or keeps a failed answer: a lockfile over 8 MiB or a symlink gets no hash and runs uncached ([#416](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/416))
- A pricing catalog refreshed by an older `self-update` no longer hides the newer one packaged in an upgraded binary ([#512](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/512))
- `--output=/dev/null` keeps discarding the report without replacing the device, and `--output` and `--generate-baseline` refuse a pipe, a socket or a block device ([#539](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/539))

### Performance Improvements 🚀

- Grouping a large project's files into feature chunks takes seconds instead of minutes (1,000 controllers and 10,000 files: 14.8 s to 0.08 s), with the same chunks ([#458](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/458))
- A controller whose public actions call each other in a long chain no longer stalls the mapping stage (6,000 methods map in under half a second) ([#469](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/469))
- One very long line no longer holds the pre-scan or the code slicer for minutes on a PHP build without PCRE JIT: the gap in several pre-scan patterns is bounded to 512 characters ([#517](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/517))
- An answer made of thousands of unclosed brackets no longer stalls the audit for minutes ([#457](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/457))
- `audit:trend` reads each report once instead of twice ([#504](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/504))
- Concurrent attacker analysis (`audit.attacker_max_concurrent` above 1) builds prompts per window, so memory no longer grows with the number of chunks (400 chunks: 83 MB to 11 MB) ([#470](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/470))
- A run with many findings no longer adds every finding's location to every chunk of the next iteration: each list names the first 100 findings and counts the rest ([#460](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/460))
- A batched review (`audit.reviewer_batch_size`) carries each file once instead of once per finding ([#459](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/459))
- A repository's `access_control` paths can no longer stall the audit by backtracking: each pattern gets 10,000 steps and the route map is rendered once, taking a hostile project from 49 seconds to 2; a route whose rule cannot be decided is tagged `UNKNOWN_ACCESS_CONTROL` ([#577](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/577))
- `audit:baseline` merges a report written by this release in time proportional to the report and the baseline, not to their product: 3,000 findings against 3,000 entries take a fraction of a second instead of a minute and a half ([#628](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/628))

### Core 🧱

- `mcp:serve`, the `audit` MCP tool and its input schema are marked experimental: they may change in any release and are no longer covered by the backward compatibility promise ([#633](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/633))
- Cached attacker and reviewer answers refresh once after upgrading ([#442](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/442), [#449](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/449), [#467](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/467), [#517](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/517), [#615](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/615))
- A custom `RecordVulnerabilityToolFactoryInterface` tool may implement `RecordingToolInterface`, answering `RecordingToolInterface::RECORDED` for a call it took in and anything else for a refusal; one that does not still records on the last tool round ([#410](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/410), [#474](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/474), [#638](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/638))
- Custom security-config parsers can implement `LoadOrderAwareSecurityConfigParserInterface` (since 1.22) to order configuration files as Symfony loads them ([#511](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/511))
- Custom scanners can implement `SkippedFileReportingProjectFileScannerInterface` to report the files they leave out ([#473](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/473))
- `AuditReport::foundNoFile()` and `AuditReport::isWithoutVerdict()` are new; `AuditReport::hasNoVerdict()` keeps its 1.21.0 meaning ([#437](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/437), [#543](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/543))
- The attacker and reviewer prompts tell the model that file contents, comments and scanner text are data to analyse, never instructions ([#449](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/449))
- Reports neutralise hostile finding text: the HTML report strips terminal escape sequences, the Markdown and GitHub comment reports no longer turn a bare URL or `www.` address into a live link, and `audit:baseline --annotate` shows a title and file as text, not console markup ([#434](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/434))
- A PHP file made of thousands of unmatched closing brackets that PHP's own parser rejects is no longer tokenized: the scrubber reads it as text, the parsers skip it with a warning and the attacker prompt marks its controller or voter `unmapped_access_control`; one that parses is read as before ([#520](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/520), [#603](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/603))
- A file whose brackets nest more than 5,000 levels deep is skipped by the access-control, voter and form parsers with a warning instead of exhausting memory or crashing the audit, and the attacker prompt marks its controller or voter `unmapped_access_control` ([#445](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/445), [#603](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/603))
- Provider API keys sent in a request URL (`?key=` on Vertex AI) are replaced with `***REDACTED***` in provider failure messages, logs, the console error line and MCP answers ([#536](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/536))
- `composer audit` runs on a private copy of `composer.lock` next to an empty `composer.json`, so the audited project cannot redirect advisories; its `config.audit.ignore`, private repositories and `auth.json` no longer apply, so configure them in the Composer home of the user running the auditor ([#419](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/419), [#547](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/547))
- Attacker, reviewer, triage-memory and advisory cache files are created `0600` and new cache directories `0700`; run `chmod -R go-rwx` on a `cache.dir` an earlier release created ([#418](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/418))
- `privacy.offline_only` no longer mistakes an `api_key` such as `user:s3cretpassword` for a platform endpoint, and a refusal names only `scheme://host[:port]`, never userinfo or a query ([#505](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/505))
- The MCP `audit` tool still runs a cost-budgeted audit on a model it cannot price, and logs a warning that `audit.budget.max_cost_usd` cannot be enforced ([#546](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/546))
- A pricing catalog with a negative, infinite or input-less price is treated as an unpriced model, a refreshed catalog the run cannot use falls back to the packaged one, and `doctor` names the catalog in use ([#430](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/430))
- `self-update` pins every request to HTTPS with TLS 1.2 or newer and bounds what it downloads (1 MiB for release metadata, 256 MiB for the binary) ([#432](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/432))
- `self-update` resolves a bare binary name through `PATH` only, so it can no longer replace a same-named executable in the current folder ([#417](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/417))
- `self-update` refuses a release tag that is not a release version (`X.Y.Z`, optional pre-release, optional leading `v`) instead of pasting it into download URLs ([#433](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/433))
- The GitHub Action's `comment-pr` step posts only the report its audit wrote, never a file a symbolic link in the pull request points at, and says why in a warning when it posts nothing ([#576](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/576))
- `--since` no longer runs a command that an audited checkout's own `.git` directory defines ([#624](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/624))

## [1.21.0] — 2026-10-04 — Gateway

### New Features ✨

- `audit:run --fail-on-incomplete` exits with the new code `3` when some file could not be fully analyzed, `--generate-baseline` included; without it the run prints an `Audit incomplete: N file(s) could not be fully analyzed` warning, on stderr when the report goes to stdout; the GitHub Action gains a `fail-on-incomplete` input and a `complete` output ([#389](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/389))
- Bill each call at the rate of the model the provider says answered it, so a gateway that routes on its own (`openrouter/auto`), a failover platform or an alias resolved to a dated release is no longer billed at the configured model's rate; `by_model` keeps the configured model and the new additive `billed_models` key names the billed ones ([#385](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/385))
- `init --provider=generic.<instance>` configures any OpenAI-compatible AI gateway behind a custom URL and token; `provider: <platform>.<instance>` selects an instance of `generic`, `openresponses`, `azure`, `bedrock`, `cache` and `failover`, and a bare or mistyped instance is refused with exit `2` naming the instances configured ([#367](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/367))
- `init --base-url` and a base-URL prompt for `albert`, `amazeeai`, `generic` and `openresponses`; an empty URL is refused with exit `2`, a URL whose every `%` starts a percent-encoded octet is written so the platform receives it as typed, and any other `%` is refused ([#367](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/367), [#371](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/371))
- `init --endpoint` writes the connection URL of `deepgram`, `elevenlabs`, `minimax`, `ollama`, `together` and `venice`, and `--no-api-key` writes no `api_key` for `bedrock`, `deepgram`, `elevenlabs`, `generic`, `ollama` and `openresponses`; `init --provider=ollama` now writes a keyless configuration with a required endpoint instead of one the next run cannot boot ([#371](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/371))
- `init` configures AWS Bedrock through its Mantle routes (`anthropic.*` models use `messages`, `google.gemma-*` use `responses`, others use `completions`), reads the key from `BEDROCK_API_KEY` and installs the bridges the route needs; `--no-api-key` signs requests with AWS SigV4, and a model that does not name its vendor is refused with exit `2` ([#386](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/386))
- `init` installs the bridge of the platforms it cannot configure (`azure`, `cartesia`, `higgsfield`, `dockermodelrunner`, `lmstudio`, `transformersphp`), prints a ready-to-edit `config.yaml` block and exits `2` without writing; `cache` and `failover` are refused with the reason, and `doctor` points at `init --provider=<platform>` for a missing bridge ([#382](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/382))
- Support the Fireworks, Together, Venice, Eden AI, TypeSafe and Higgsfield platforms of `symfony/ai` 0.14 ([#380](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/380))
- The standalone binary stores your provider API key: `init` asks for it with hidden input, `auth:set` stores or replaces it, `auth:status` reports which key an audit would use and where it comes from, and `auth:remove` forgets it; an exported variable still wins over the stored key ([#361](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/361))
- The stored key lives in an owner-only `credentials.json` beside the config file and an exposed file is refused rather than used; the audit header, `auth:status` and `doctor` show the key as a masked preview, plus a fingerprint in the last two, never in full ([#361](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/361))
- `%env(file:VAR)%` reads the provider credential from the file `VAR` names in the standalone configuration, for Docker and Kubernetes secrets, `systemd` `LoadCredential=` or a plain `0600` file ([#361](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/361))
- A run with no API key opens with `No API key available.` and names `auth:set --env-var=<VAR>`, an `export` or a password-manager prefix as ways out, `doctor` names the key that resolved, and `init` no longer prints a paste-ready `export` line that would land the key in the shell history ([#361](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/361))
- `init` says it is downloading the bridge and lists the provider, model and API-key variable it resolved, refuses a `--provider` or `--model` holding control characters, and `init --help` documents its defaults ([#367](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/367), [#391](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/391))
- `symfony-security-auditor mcp:serve` serves the auditor over the Model Context Protocol from the standalone binary, as `bin/console mcp:serve` does in bundle mode ([#384](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/384))
- The audit header names a project `.symfony-security-auditor.yaml` layered over the user config ([#391](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/391))
- A project `.symfony-security-auditor.yaml` may no longer set `cache`, `privacy`, `audit.custom_skills`, `scan.secret_scrubbing` or `scan.custom_risk_patterns`, loosen `audit.budget`, or replace a whole section with a non-map; the run stops naming the key, so move these settings to your user config, which keeps them ([#391](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/391), [#397](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/397))
- A project config accepts `model`, `attacker_model`, `reviewer_model` and `audit.escalation.cheap_model` only as a plain model id (options such as `?temperature=…` belong in your user config), refuses values or keys holding control characters, `::` or `##[` naming the key without echoing it, and refuses a file expanding to 10,000 values or more ([#391](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/391), [#397](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/397))
- A project config may no longer use `%env()%`, `%name%` or `%%` references, so it cannot read your environment (write the value itself or move the setting to your user config), and a project config that is a symlink is refused before it is read ([#391](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/391))
- On a GitHub Actions runner, reports, errors, progress lines, the `--show-scanned` listing and `audit:diff` defuse text a runner would read as a workflow command (`::…`, `##[`); the `github` format and reports saved with `--output` are unchanged ([#389](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/389), [#391](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/391))
- A route covered only by an `access_control` rule the production application never loads (under `when@test`, a non-production config folder, a file nothing imports) is `LACKS_ACCESS_CHECK` again, and the attacker prompt presents the coverage it shows as read from the repository's YAML, not verified ([#396](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/396))
- The secret scrubber redacts credential keys written without a separator (`SECRETKEY=`, `APIKEY=`, `DBPASS=`, `PGPASSWORD=`) and the `PASS` and `PW` suffixes (`DB_PASS=`, `MYSQL_ROOT_PW=`, `pass: '…'`), leaving `MONKEY`, `MAX_PW_LENGTH` and `BYPASS_CACHE` alone ([#390](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/390))
- The secret scrubber redacts PGP private keys, Symfony XML `<parameter>` and `env(…)` parameter defaults, `define()` constants, bare `token` keys, GitLab, Hugging Face, npm, SendGrid and PyPI tokens and Discord webhook URLs, but leaves code values such as `$token = $request->get('token')` as written ([#390](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/390))
- A file the secret scrubber cannot evaluate is recorded as not analyzed, so the report is incomplete, `audit:run` prints its `Audit incomplete` warning and `--fail-on-incomplete` exits `3`; a long credential-named line no longer blanks the whole file ([#396](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/396))

### Bugfixes 🐛

- Installing the bundle with `composer require --dev` no longer breaks the host application's container: the bundle registers its own clock service, since `Psr\Clock\ClockInterface` exists only when `symfony/clock` is a non-dev package ([#403](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/403))
- The reviewer sees the code of a finding the attacker reported as `./src/…` ([#388](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/388))
- A chunk the model cannot fit is split in two and each half analyzed, instead of aborting the audit on `context_length_exceeded` or an HTTP `413`; a single file that still does not fit is recorded as errored, and when the prompt's fixed part leaves no room the run stops at once, naming the remedy ([#387](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/387), [#388](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/388))
- A review batch or finding the model cannot fit no longer aborts the audit: the batch is split until every part fits, and a lone finding that still does not fit is recorded as errored ([#388](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/388))
- An answer cut off by the output limit or withheld by a content filter, whether reported as a stop reason or an error, is recorded as errored and the audit goes on; it is never cached as "no findings" or counted as a rejected finding, and a garbled tool call is retried ([#387](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/387), [#388](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/388), [#399](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/399))
- `audit.budget` is checked before each call is dispatched, and requests a concurrent window leaves in flight when it ends early are cancelled and booked, as are degraded answers, so the report and `estimated_cost_usd` no longer undercount ([#387](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/387))
- A finding that quotes a Markdown code block keeps its backticks, and a baseline-accepted finding the attacker re-reports in a later iteration stays out of the report ([#387](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/387), [#388](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/388))
- A call failing on a dropped connection (TLS EOF, `Empty reply from server`, `Broken pipe`, a partly transferred body), a refused connection, a DNS failure or a genuine rate limit whose body quotes a number like `404` is retried instead of aborting the audit ([#375](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/375), [#387](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/387))
- A concurrent conversation whose retries run out aborts the audit, as the sequential one does, and `LLM call failed after N attempts` counts every attempt ([#399](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/399))
- A finding whose review failed is no longer fed back to the attacker as rejected ([#398](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/398))
- In `lean` mode the attacker's `read_file`, `grep` and `list_files` tools see the whole project again, and `grep` no longer fails when one file is not valid UTF-8 ([#388](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/388))
- The escalation deep pass no longer treats the cheap model's findings as reviewer-validated: it receives them as unverified candidates to confirm, refine or discard, and a cheap finding on a file it judged is dropped ([#388](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/388))
- Cost is priced at the rate of the platform serving the model for the 20 `symfony/ai` platforms with a catalog listing (Bedrock, Azure, Vertex AI, OVH, Scaleway, Hugging Face, …), no longer at another provider's rate or `$0.00` ([#383](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/383))
- A report never calls a partial audit clean: the human formats print `Audit incomplete: N file(s) could not be fully analyzed` and qualify the risk level, JUnit adds an errored `Audit completeness` case, the JSON report gains `complete`, SARIF gains `invocations[0].executionSuccessful` and the Action badge turns `incomplete` ([#378](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/378), [#389](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/389))
- A run that analyzed no file and found nothing has no verdict: it exits `1` with `RISK LEVEL: UNKNOWN`, `--generate-baseline` leaves the baseline untouched, the `audit` MCP tool answers with an error, and a `--dry-run` report says none of its files was analyzed ([#398](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/398))
- Live progress shows `✗ chunk 2/5 failed` for a chunk the attacker could not analyze and `✗ review failed` for a review that reached no verdict, which the review tally counts as `failed`, not `rejected` ([#388](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/388), [#398](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/398))
- `audit:diff`, `audit:trend` and `audit:baseline --prune` no longer treat a finding as fixed, or prune it, when the later run did not analyze its file: `audit:diff` lists it as `unverified`, trend points gain an `unverified` count, a prune keeps the entry and its reason, and the JSON report gains a `scope` key ([#389](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/389), [#398](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/398))
- The `audit` MCP tool says why it failed and applies the configured baseline, `audit.excluded_types` and `audit.included_types`, as `audit:run` does ([#389](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/389), [#398](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/398))
- An `--output` or `--generate-baseline` path that could never be saved to (a symlink, a directory, a path beneath a file) is refused before the audit runs, and a failed save prints the report and keeps the abort reason ([#398](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/398))
- The secret scrubber no longer hides the code an audit has to read: `$password = $request->get('password');`, `'secret' => getenv('APP_SECRET')` and a `WHERE password = '" . $pw . "'` concatenation stay as written ([#390](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/390))
- The same project is chunked the same way on every machine, because files are scanned in relative-path order ([#390](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/390))
- A stale `$PWD` no longer points the standalone binary at another directory's `.symfony-security-auditor.yaml`, and a relative `SYMFONY_SECURITY_AUDITOR_HOME` is refused instead of silently ignored: set it to an absolute path or unset it ([#391](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/391))
- A `%env(trim:…)%` or other env-processor placeholder in a standalone config stops the run saying the binary reads only `%env(VAR)%` and `%env(file:VAR)%`, and an API key or URL holding `%` reaches the provider exactly as stored; `init` refuses such a placeholder as a base URL or endpoint and a `%…%` pair in `--model` ([#377](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/377), [#391](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/391))
- With several platforms configured, a key the selected `provider:` does not use no longer stops the run, and `audit --show-scanned` no longer needs a provider credential in the standalone binary ([#397](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/397))
- The standalone binary waits up to ten minutes for a provider to start answering instead of 60 seconds, and the new standalone-only `http_timeout` key sets the seconds; a project config may raise it, never lower it ([#397](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/397))
- `init` holds the bridge tree to the `symfony/ai-platform` release the binary bundles, and a tree built by 1.20.x is refused with the `init --force` command that rebuilds it; when upgrading from 1.20.x run `symfony-security-auditor init --provider=<your provider> --force` once ([#391](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/391), [#397](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/397))
- A bridge the binary cannot load, or a platform whose bridge is not installed, now names `symfony-security-auditor init --provider=<provider>` instead of killing every command or suggesting `composer require`; `init` also refreshes the pins of a bridge manifest written before 1.15 ([#391](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/391), [#397](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/397))
- `init` writes every value so it reads back as the string it was, asks to overwrite a configuration only after every refusal, refuses any platform `symfony/ai-bundle` does not declare (Meta/Llama is no longer listed; use `generic`) and requests the right package for five misnamed bridges ([#367](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/367), [#391](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/391))
- `--help`, `help`, `list --format=json|xml|md` and shell completion work for the standalone `audit` and `mcp:serve` commands before `init` has run ([#384](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/384), [#391](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/391))
- The standalone binary boots against Ollama ([#366](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/366))
- `self-update` refuses a binary whose directory it cannot write to before downloading anything, prints `Downloaded and verified <new>` instead of claiming `Updated` before the swap, and a swap that fails exits `1` with a readable error and the previous version still installed ([#392](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/392))
- `install.sh` replaces an existing binary atomically and cleans up its staged copy when interrupted, and `install.ps1` downloads at full speed on Windows PowerShell 5.1 ([#392](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/392))
- The standalone update check no longer contacts GitHub on every command when its cache directory cannot be written, and `mcp:serve` sends PHP notices and warnings to stderr so they cannot corrupt the JSON-RPC stream ([#392](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/392))

### Performance Improvements 🚀

- A model's price is resolved once per run, and a concurrent tool-using window ends as soon as every conversation has its answer ([#387](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/387))
- Long attacker runs spend less time between LLM calls, and `audit:diff` of two large reports no longer grows quadratically ([#388](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/388), [#389](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/389))
- Scrubbing half a megabyte of `-----BEGIN PRIVATE KEY-----` headers no longer takes 11 seconds ([#396](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/396))

### Core 🧱

- Runs on `symfony/ai` 0.14 (`symfony/ai-bundle` `^0.14`): in bundle mode raise every `symfony/ai-*-platform` bridge your application requires to `^0.14` in the same update, and in the standalone binary rebuild the bridge tree once with `init --force` ([#380](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/380))
- `mcp:serve` runs on `mcp/sdk` `^0.8.1`, for the bundle and the standalone binary; in bundle mode an application holding `mcp/sdk` at 0.7 must let it move to 0.8 ([#358](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/358))
- `symfony/http-client` and `symfony/clock` are now direct dependencies and `symfony/models-dev` requires `>=130.0` ([#366](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/366), [#383](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/383), [#403](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/403))
- The package no longer requires the `uri` extension, which only PHP 8.5 ships; `league/uri-polyfill` supplies it below ([#404](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/404))
- Cached attacker answers refresh once after upgrading, and reviewer verdicts cached with false-positive feedback are reviewed once again ([#388](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/388), [#390](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/390), [#398](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/398))
- Baseline entries reach the reviewer capped (`type` 64, `file` 512, `title` 300, `reason` 5,000 characters), quoted as data and within a bounded section, and attacker prompt preambles fold every Unicode line break in a file path or risk-marker description ([#388](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/388), [#398](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/398))
- The JSON path of the attacker and reviewer takes the last top-level block of an answer that decodes to an object or a list holding one, so quoted examples and brackets in prose such as `[1]` no longer stand for the answer ([#399](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/399))
- A value pasted into `--env-var` is masked or escaped instead of printed, and a relative `$HOME` is treated as unset so the config, credentials and cache directories never resolve inside the audited project ([#391](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/391))
- `lookup_advisory` also reads Composer's ignored advisories, so the audited project's `config.audit.ignore` does not hide a vulnerable dependency ([#390](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/390))
- A symlinked directory above a report, baseline or cache file is refused, and a symlink committed in the audited repository can no longer lead the scanner outside the project ([#390](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/390))
- The standalone quickstart reads the API key from stdin instead of `export ANTHROPIC_API_KEY=sk-…`, so the key never lands in your shell history ([#354](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/354))

## [1.20.1] — 2026-08-23 — Herald

### New Features ✨

- The standalone binary prints its identity banner on every command (`--version`, `-h`, `doctor`, `init`, `self-update --check`, …) instead of only `audit`, once per run and on stderr so `--version` and `list --format=json` keep a clean stdout; the completion commands stay bare ([#348](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/348))
- The identity banner carries the project homepage under the wordmark ([#348](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/348))
- A failed standalone command echoes `Command: symfony-security-auditor <args>` under the rendered error, even with `-q`, so a pasted CI log shows the invocation that failed ([#348](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/348))
- The `--dry-run` cache-discount caveat is a dimmed footnote instead of a framed `[NOTE]` block ([#348](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/348))

### Bugfixes 🐛

- `audit --dry-run`: no longer needs a provider credential in the standalone binary, so a project can be priced before signing up for an API key; a real run and `doctor` still report a missing key ([#348](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/348))

## [1.20.0] — 2026-08-22 — Ledger

### New Features ✨

- `--dry-run` counts the attacker's skill-prompt overhead on every chunk and iteration, which `audit.stable_system_prompt` (default `true`) makes sizeable, so estimates no longer undercount real spend ([#336](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/336), [#345](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/345))
- `--dry-run` counts tool round-trip overhead when `audit.tools_enabled` is on, scaled by `audit.max_tool_iterations`, so lowering that option lowers the estimate ([#337](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/337), [#345](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/345))
- `--dry-run` warns on stderr when `audit.poc_synthesis.enabled` or `audit.fix_synthesis.enabled` is on, since neither stage's cost is part of the estimate ([#338](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/338))
- `--dry-run` presents the reviewer figure as a rough floor, stating the ratio to attacker input it works out to and that real cost scales with the findings found ([#339](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/339))
- `self-update` refreshes the pricing catalog after replacing the binary, so a long-lived install picks up new models and prices; it also refreshes when the binary is already current, `--check` never does, and it is skipped under `privacy.offline_only` ([#335](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/335))
- A failed pricing refresh never fails `self-update`: it warns that cost figures keep using the catalog already in place and that re-running `self-update` retries ([#335](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/335))
- `doctor` and `--version` show which `symfony/models-dev` pricing snapshot the binary prices from, naming the refreshed file when one is in use ([#334](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/334))
- A run with zero findings shows a one-line `review skipped` acknowledgment instead of jumping from the last chunk to the report, with its own wording when every finding was baseline-accepted or the run is aborting ([#333](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/333))
- The console, Markdown and HTML reports show a `Cost` line labeled "published rates", or "no published pricing, or a self-hosted model" when tokens were spent on a model without a published rate, judged per model ([#332](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/332))
- `--format=json` reports gain a `by_model` cost object next to `by_role`, with `cache_read_tokens` and `cache_creation_tokens` per model ([#332](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/332))
- The CLI header is a branded `◉ >> SECURITY AUDITOR` wordmark with a tagline, laid out the same in CI logs and dropping the `◉` when the locale is not UTF-8 ([#331](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/331))
- `--show-scanned` labels the catch-all buckets `php · uncategorized` and `other · uncategorized` and lists them last; the `included_types` and `excluded_types` values are unchanged ([#330](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/330))
- `--show-scanned` and `--dry-run` close with one light confirmation line instead of a boxed `[OK]` block ([#329](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/329))
- `init` prints a copy-pasteable `export ANTHROPIC_API_KEY=` line instead of naming the variable in prose ([#328](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/328))
- Secret scrubbing redacts `Authorization: Basic` credentials, keeping the header and scheme (`Authorization: Basic ***REDACTED:basic_authorization***`), and Slack `xapp-` app-level tokens ([#343](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/343))

### Bugfixes 🐛

- `scan.import_sarif`: results whose file path a URI has to escape (a space as `%20`) were silently dropped, including the auditor's own SARIF; artifact URIs are now percent-decoded before matching ([#344](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/344))
- `scan.code_slicing`: the configuration reference no longer promises whole method bodies; it states that retention is per line and that a file should go unsliced when the taint flow between source and sink matters ([#343](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/343))
- The pipeline line in the CLI header uses `->` and `vs` instead of two characters a Windows console cannot show ([#331](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/331))
- `self-update`: an unreadable download now fails with a clear message instead of a `TypeError`, and the downloaded temp file is removed on any failure ([#340](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/340))
- `self-update`: no longer reports a stale "update available" notice for up to a day after a successful update ([#340](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/340))
- `self-update`: no longer ends in a phar corruption fatal error after a successful update, because the binary swap now happens at process exit ([#341](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/341))
- `self-update --check`: the passive update notice now agrees with the version `--check` just reported instead of staying silent for up to a day ([#341](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/341))
- `RegexCodeSlicer`: a heredoc body line that merely starts with the closing identifier no longer ends the heredoc early, which could elide a real SQL injection sink from the attacker ([#345](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/345))
- A fully positional `#[Route(...)]` attribute keeps its `methods` restriction instead of reporting none ([#345](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/345))

### Core 🧱

- PoC and fix synthesis prompts escape a finding's `file` path like every other field, so a crafted path cannot forge a section header ([#345](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/345))
- `docs/architecture.md`'s exit-code and `--format` summary matches the canonical table in `docs/configuration.md` ([#343](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/343))

## [1.19.1] — 2026-08-13 — Lineage

### Core 🧱

- The release workflow verifies that a push-triggered release commit is a genuine merge commit whose second parent is on `1.x`, and fails loudly on a squash- or rebase-merge; `main` and `1.x` are reconciled with a proper merge ([#321](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/321))

## [1.19.0] — 2026-08-12 — Bulwark

### New Features ✨

- The attacker detects XSSI "JSON Hijacking": a `GET` endpoint returning a bare top-level JSON array instead of an object, exploitable through a cross-origin `<script src>`; new `json_hijacking` finding type (CWE-200, OWASP A01:2025), not flagged on routes that exclude `GET` ([#284](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/284))
- Every report carries a normalized 0-100 score and an `A`-`F` grade next to the risk level (`A` safe, `B` low, `C` medium, `D` high, `F` critical); `--format=json` gains the root keys `score` and `grade`, and the executive summary shows both ([#262](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/262))
- `audit:run --min-score=<0-100>` exits `1` when the score falls below the threshold, independently of `audit.fail_on`; the GitHub Action mirrors it as the `min-score` input ([#263](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/263))
- The GitHub Action can write a shields.io badge endpoint file with the report's grade (opt-in `update-badge` input, `badge-path` input, `grade` and `badge-path` outputs); committing the file stays up to you ([#264](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/264))
- `--format=github-comment` renders the grade, score and ten most severe findings as a pull request comment body, and the Action's opt-in `comment-pr` input posts it and edits it in place on each push, with a `comment-url` output ([#265](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/265))
- The Action's `comment-pr` step only edits comments authored by `github-actions[bot]`, so a pull request commenter can no longer hijack the report comment by posting its marker first ([#290](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/290))
- The standalone binary rejects a project `.symfony-security-auditor.yaml` that declares `platform` or `provider`, naming the file and keys, so an audited repository cannot redirect the LLM connection and your API key to its own endpoint; `doctor` reports the same failure and connection settings come from the user config only ([#278](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/278))
- The standalone binary rejects a project `.symfony-security-auditor.yaml` that declares `scan.import_sarif`; configure SARIF imports in the user config instead ([#304](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/304))
- `scan.included_paths` entries that resolve outside the audited project root are skipped with a warning instead of being read and sent to the LLM provider ([#304](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/304))
- `scan.custom_risk_patterns` are validated at startup (an empty or invalid pattern throws `InvalidCustomRiskPatternException`), and a pattern that fails at runtime logs a warning and stops running for the rest of the file ([#304](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/304))
- Secret scrubbing fails closed: a file the scrubber cannot finish scanning is replaced by `***REDACTED:unscannable***`, keeping its line count, with a warning naming the pattern ([#280](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/280))
- Secret scrubbing redacts `aws_secret_access_key`, `secret_key_base`, `client_secret_value` and `private_key_path` in YAML, PHP-array and JSON form as it already did in dotenv form, and recognizes `PASSPHRASE` as a credential word ([#280](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/280))
- Secret scrubbing redacts Azure Storage connection strings (`AccountKey=`), `Authorization: Bearer` headers, OpenAI-style `sk-` and `sk-proj-` keys, and Slack incoming webhook URLs ([#303](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/303))

### Deprecations 💀

- `SymfonyMapping::voterCapabilities()`, `firewallRules()`, `controllersWithoutVoters()` and `hasVoterForEntity()` are deprecated, in favour of `authorizationRules()`, `perimeterRules()`, `entrypointsWithoutAuthorizationRule()` and `hasAuthorizationRuleForModel()` on `ApplicationSecurityMap` (via `SymfonyMapping::toApplicationSecurityMap()`); the rest of `SymfonyMapping` stays until the next major ([#267](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/267))

### Bugfixes 🐛

- `audit:run`: an audit that examined no files (mistyped `project-path`, `scan.included_paths` matching nothing, an over-broad `excluded_paths`) exits `1` instead of reporting SAFE, score 100, grade A and exit `0`; `AuditReport::filesDiscovered()` exposes the count ([#288](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/288))
- `audit:run`: a failing `--min-score` gate no longer blames the `--fail-on` threshold; the message now reads `Audit failed a configured gate. Risk: %s. Score: %d/100.` ([#276](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/276))
- `audit.budget.max_tokens` counts cache read and cache creation tokens as well as input and output, so a caching-heavy run can no longer pass the cap unnoticed; the cap may trip earlier than before ([#288](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/288))
- Attacker chunk cache entries no longer outlive the security mapping (`security.yaml` access control, voters, routes, forms) they were computed under; a custom `AttackerCacheInterface` that is not context-aware will see chunks skipped more often ([#288](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/288))
- `record_vulnerability` requires `line_start`, so a finding that omitted it can no longer overwrite an unrelated finding of the same type in the same file ([#288](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/288))
- Finding ids (`VULN-…`) no longer collide when a digit can move between the file path and the start line ([#292](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/292))
- A purely numeric `file_path` no longer crashes `audit:run --format executive` with a `TypeError` ([#289](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/289))
- Finding titles and file paths are sanitized against forged prompt sections (carriage returns stripped from attacker, reviewer and Symfony-mapping prompts) and against bidirectional overrides in SARIF and JUnit reports, even when the title also holds invalid UTF-8 ([#289](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/289))
- `audit:run --since` no longer executes commands defined by the audited repository's git config (`core.fsmonitor`, or a `.gitattributes` clean filter); uncommitted changes are read with plumbing commands that never run a content filter ([#290](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/290))
- The MCP `audit` tool resolves advisories, SARIF imports and triage cache entries against the audited project instead of the bundle directory, and rejects a non-absolute `path` ([#290](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/290))
- A negative token count from the LLM provider can no longer defeat the configured rate limit for the rest of its window ([#291](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/291))
- Standalone configuration resolves `%env(...)%` placeholders outside the `platform` block, so `model: '%env(SSA_MODEL)%'` no longer aborts ([#268](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/268))
- Standalone binaries are published with releases again, after 1.18.0 shipped none because the static build rejected the polyfilled `ext-uri` requirement ([#229](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/229))

### Core 🧱

- `audit:run` no longer runs the audited project's Composer scripts or plugins during the advisory lookup (`composer audit` now gets `--no-scripts` and `--no-plugins`); with an earlier release, assume the project's Composer scripts ran ([#277](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/277))
- The scan segfault on a line with thousands of `/**/` pairs and the quadratic stall on long `$this->helper()` call chains are gone, with identical slicing and mapping output ([#301](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/301), [#297](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/297))
- A finding title can no longer ping a GitHub account through the pull request comment (`@` is entity-encoded), and a `|` in a file path can no longer forge a table column ([#276](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/276))
- Finding fingerprints are computed field by field, so a crafted `title` or `filePath` can no longer share a fingerprint with an unrelated finding and suppress it through the baseline or the CI gate ([#294](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/294))
- Cache keys and digests for the security mapping, reviewer feedback, merged feedback and the triage memory are hashed field by field, so two different inputs can no longer produce the same key and replay a stale verdict ([#303](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/303))
- The release pipeline verifies the SHA-256 of the `static-php-cli` download before running it ([#296](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/296))
- `FrameworkVocabulary` carries the framework name, template language and idiomatic fixes the PoC and fix synthesizers interpolate into their prompts, as an optional fourth constructor argument defaulting to Symfony ([#268](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/268))
- `ApplicationSecurityMap` exposes the project survey under framework-neutral names (`entrypoints()`, `authorizationRules()`, `perimeterRules()`, …) and `SurfaceArchetype` gives every scanned file a framework-neutral shape through `ProjectFile::archetype()`; both are additive ([#267](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/267), [#266](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/266))
- `RegexCodeSlicer` is split into single-responsibility collaborators with identical output ([#302](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/302))
- The release installers (`install.sh`, `install.ps1`) and `resources/schema.json` are attached to each release as assets; the documented URLs still point at `main` ([#254](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/254))
- `main` holds exactly the latest release, development happens on `1.x`, and every pull request declares a target branch that the new `Pull request target` workflow checks against its base ([#254](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/254))
- CI runs on pushes to version branches such as `2.x`, and resolves the root package version deterministically through `COMPOSER_ROOT_VERSION` ([#254](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/254), [#256](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/256), [#255](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/255))

## [1.18.0] — 2026-07-26 — Airgap

### New Features ✨

- `audit:run --format=executive` renders a one-screen stakeholder summary: risk level and score, a business-impact sentence, and findings by severity, by type and the five most-affected files, with no per-finding detail and no extra LLM call; a report with only low-impact findings reads "Negligible business exposure" ([#214](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/214), [#224](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/224))
- `privacy.offline_only: true` makes the auditor refuse every network call it owns: no `composer audit` advisory lookup, and the standalone binary aborts before booting if a platform endpoint is not loopback, link-local or private-range, IPv4-mapped IPv6 hosts included; in bundle mode the platform in `ai.yaml` stays yours to check ([#215](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/215), [#223](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/223))
- The HTML report gains a "Distribution" section with self-contained inline-SVG bar charts of findings by severity and by vulnerability type that follow the reader's light/dark theme, and no longer prints the "Summary by severity" table that repeated the same counts ([#216](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/216), [#221](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/221))

### Bugfixes 🐛

- Concurrent analysis (`audit.attacker_max_concurrent` above `1`, as in the `fast` profile): an unexpected error in one batch no longer drops every later file from the audit, only the failing batch is lost, as in sequential mode ([#225](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/225))

## [1.17.0] — 2026-07-23 — Preflight

### New Features ✨

- The standalone binary prints a one-line notice on stderr, after a command on an interactive terminal, when a newer release is available; the lookup runs at most once per 24 hours, never changes an exit code, stays silent on Windows and is disabled with `SSA_NO_UPDATE_CHECK=1` ([#197](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/197), [#201](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/201))
- `curl -fsSL …/install.sh | SSA_INIT=1 sh` installs and configures the standalone binary in one command: after the checksum check the installer runs `init`, interactively when a terminal is reachable and with `--no-interaction` otherwise; a failed `init` keeps the installed binary ([#191](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/191))
- `install.sh` points Git Bash, MSYS and Cygwin users at the PowerShell installer, and the install docs lead with the `curl … | sh` one-liner ([#191](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/191))
- `init` accepts `--provider`, `--model` and `--env-var` for scripted setups such as `init --provider=openai --model=gpt-5.4 --no-interaction`; blank values or an invalid variable name exit `2` before anything is written, and the bridge is installed before the configuration file so a failed install keeps the previous setup ([#193](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/193), [#210](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/210))
- `init --force` overwrites an existing configuration without asking, so a CI pipeline can switch providers instead of silently keeping the old one ([#204](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/204))
- The standalone-only `doctor` command checks the configuration, the provider bridge (by actually booting the audit with it) and Composer, printing one line each and exiting `0` on pass or warning and `1` on failure, so `symfony-security-auditor doctor && symfony-security-auditor audit` works as a CI preflight ([#196](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/196), [#210](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/210))

### Bugfixes 🐛

- `init`: a provider spelled as a bridge package slug (`open-ai`, `deep-seek`, `vertex-ai`, …) is normalized to its platform key (`openai`, …), instead of writing a configuration every later `audit` rejects ([#202](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/202))
- `self-update`: a release tag with a leading `v` no longer disables update detection, since it is compared and shown without the `v` ([#210](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/210))
- `self-update`: release-metadata lookups give up after 10 seconds to connect and 20 seconds in total instead of stalling a command on a black-holed network, while binary downloads keep their 600-second window ([#210](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/210))
- `self-update`: the macOS path fallbacks accept only executable regular files, so a stray same-named file or directory is never replaced instead of the running binary ([#205](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/205))
- `self-update`: it resolves the running binary on macOS when launched by a bare name found on `PATH` ([#194](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/194))
- `self-update`: it fails immediately on native Windows, where no self-update path is published, instead of looking up the release first and reporting "Already up to date" ([#201](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/201))
- `install.sh`: a failed `wget` download now prints its HTTP error instead of aborting silently ([#192](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/192))
- `install.ps1`: the "no Windows binary for this release" guidance now shows on PowerShell 7 as well as Windows PowerShell 5.1 ([#192](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/192))

## [1.16.0] — 2026-07-18 — Perimeter

### New Features ✨

- The attacker flags HTTP trust-boundary misconfigurations: a wildcard `trusted_proxies` (`0.0.0.0/0`, `::/0`) that lets clients spoof `X-Forwarded-*`, and `getHost()`-style calls building links without `trusted_hosts`, as the new `trusted_proxy_misconfiguration` and `host_header_injection` finding types ([#172](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/172), [#188](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/188))
- The attacker hunts weak password hashing, `remember_me` with `secure: false`, NelmioCors `origin_regex: true`, CSP `'unsafe-inline'` / `'unsafe-eval'`, disabled HSTS and `APP_DEBUG=1`, as new finding types `weak_password_hashing`, `permissive_cors_origin`, `weak_content_security_policy`, `missing_transport_security` and `debug_mode_enabled` ([#175](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/175), [#188](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/188))
- A `RememberMeBadge` attached to every login regardless of a user-submitted "remember me" flag is now flagged ([#175](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/175))
- The attacker audits LDAP services, Sonata Admin and EasyAdmin panels: unescaped LDAP filter or DN concatenation, admin panels exposing privileged fields (`roles`, `password`, `isAdmin`) or lacking per-object access control, and EasyAdmin actions not scoped by `->setPermission()` ([#180](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/180), [#188](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/188))
- The new `permissive_mercure_topic_selector` finding type covers a Mercure JWT `publish` / `subscribe` claim scoped to `*`, and the recipe's default JWT secret placeholder is flagged ([#180](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/180))
- `audit.since_closure: none|direct` widens a `--since` run to the controllers guarded by a changed voter, so a voter edit that weakens an unrelated controller is still caught in CI; `thorough` defaults to `direct`, `balanced` and `fast` to `none`, and an explicit value always wins ([#174](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/174))
- Imported SARIF results with a taint-tracking `codeFlows` path show the attacker the full source-to-sink path, with `...` marking steps dropped for pointing outside the scan surface ([#176](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/176), [#184](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/184))
- `audit.triage_memory: true` has the reviewer remember its rejections across runs: each explained rejection is kept per audited project under `<cache.dir>/triage-memory/` (500 entries max) and shown to later reviews beside `audit.baseline` reasons, in every review mode ([#177](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/177), [#184](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/184), [#188](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/188))
- Triage-memory feedback is presented to the reviewer as non-authoritative and newest first, with each reason capped at 5000 characters, and the reviewer verdict cache keeps working when it is on ([#184](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/184), [#188](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/188))
- Truncated or content-filtered LLM responses now log an actionable warning (pointing at `max_output_tokens` for truncation) instead of surfacing as silent finding loss, and HTTP 5xx server errors are retried as transient ([#183](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/183))
- MiniMax is supported as a provider through `symfony/ai-mini-max-platform` and its `MINIMAX_API_KEY` variable, with token estimation calibrated for `MiniMax-M2` models ([#181](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/181))
- `symfony-security-auditor self-update` replaces the standalone binary in place after verifying the release's SHA-256 checksum, and `--check` only reports whether an update exists; it refuses to run outside the standalone binary, never installs from a shared download path and gives up on a stalled network after 600 seconds ([#166](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/166), [#184](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/184))
- The GitHub Action gains `mode: standalone` (runs the checksum-verified binary from the pinned action version instead of the bundle), a `fail-on` input and the outputs `exit-code`, `report-path`, `findings-count` and `highest-severity`, which are written even when the audit fails ([#173](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/173), [#184](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/184))

### Bugfixes 🐛

- A YAML config file with numeric top-level keys no longer crashes the audit with a `TypeError` before any LLM call ([#188](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/188))
- The native Windows binary is published with releases again ([#168](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/168))

### Core 🧱

- Cached attacker answers refresh once after upgrading ([#172](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/172), [#175](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/175), [#180](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/180), [#188](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/188))
- `symfony/ai-bundle` requirement moves to `^0.11` ([#179](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/179))
- `Vulnerability::of()` accepts an optional `detectedAt` timestamp, defaulting to the current time ([#185](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/185))
- `ReviewerFeedbackProviderInterface` is now composable and the new `TriageMemoryRecorderInterface` joins it as a documented extension point ([#177](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/177))
- Imported SARIF marker text is collapsed to a single line before it reaches the attacker prompt, so a crafted message cannot inject a fake prompt section ([#184](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/184))
- The release build verifies the SHA-256 of its Launchpad `.deb` fallback before installing it ([#184](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/184))

## [1.15.0] — 2026-07-14 — Conduit

### New Features ✨

- `bin/console mcp:serve` runs a Model Context Protocol server over stdio that exposes an `audit` tool taking a project `path` and returning the JSON report, so an MCP client such as Claude Desktop or an IDE agent can run a full audit through the same pipeline as `audit:run` ([#162](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/162))

### Bugfixes 🐛

- The standalone binary's `init` installs a provider bridge its own bundled PHP can load, instead of resolving dependencies against the host's PHP and aborting at startup ([#164](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/164))

## [1.14.0] — 2026-07-14 — Beacon

### New Features ✨

- `audit:trend --format=html` renders the finding-count timeline as a single self-contained HTML page with a line chart and a table of each report's total and new/fixed deltas ([#146](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/146))
- `audit:baseline report.json [baseline.json]` maintains the accepted-finding baseline from an existing JSON report without an LLM run: existing entries and their `reason` stay, only uncovered findings are appended, `--prune` drops entries whose findings are gone and `--annotate` asks a reason for each new one ([#148](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/148))
- `audit:trend` tracks finding counts across two or more JSON reports, showing each report's total and how many findings appeared and disappeared since the previous one, as a console timeline or with `--format=json` ([#136](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/136))
- A baseline entry's `reason` teaches the reviewer: reasons from the effective baseline (`--baseline` or `audit.baseline`, 20 entries max) are given as maintainer-trusted hints, without letting it reject a finding merely because it resembles an accepted one, and editing a `reason` re-reviews the affected findings; `ReviewerFeedbackProviderInterface` lets integrators plug in other sources ([#137](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/137))
- `scan.import_sarif` imports SARIF 2.1.0 reports from tools such as Psalm, PHPStan, Progpilot or Semgrep as attacker risk markers at their file and line, with relative paths resolved from the project root and a missing or malformed file aborting the audit ([#138](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/138))
- `audit.custom_skills` adds attacker skills from configuration alone, each with a `file_type` bucket, free-form `instructions` and an optional `priority`, merged into the prompt whenever a file of that type is in the chunk ([#139](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/139))
- `audit.fix_synthesis.enabled` attaches a suggested unified-diff patch, in the new `suggested_fix` JSON field and in the console, Markdown and HTML reports, to each validated finding at or above `audit.fix_synthesis.severity_floor` (default `high`); it is off by default ([#140](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/140))
- Every finding carries a heuristic CVSS v4.0 estimate in a `cvss` object (`version`, `vector`, `base_score`) in JSON, and in SARIF as `security-severity` plus a `cvssV4_0Vector` property ([#141](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/141))
- `SYMFONY_SECURITY_AUDITOR_HOME` redirects the standalone binary's config, cache and bridge directories to a writable folder, outranking the XDG variables and `$HOME`, and a failed config write now names it as the way out ([#161](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/161))

### Breaking Changes 💥

- Standalone macOS binaries are named `symfony-security-auditor-macos-x86_64` and `-macos-arm64` instead of `…-darwin-…`; `install.sh` picks the new name, so anyone hardcoding a download URL must switch `darwin` to `macos` ([#158](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/158))

### Bugfixes 🐛

- `init` installs the right provider bridge for platforms with a hyphenated package slug (`openai` → `symfony/ai-open-ai-platform`, and likewise `deepseek`, `vertexai`, `openresponses`, `huggingface`, `elevenlabs`, `amazeeai`) ([#161](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/161))
- `init` proposes a valid API-key variable for hyphenated provider names, such as `OPENAI_API_KEY` instead of `OPEN-AI_API_KEY` ([#161](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/161))

## [1.13.0] — 2026-07-12 — Groundtruth

### New Features ✨

- File uploads are a first-class attack surface, with a dedicated pre-scan bucket, chunking slot and attacker-skill block ([#118](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/118))
- Twig extensions are a first-class attack surface, with a dedicated pre-scan bucket, chunking slot and attacker-skill block ([#119](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/119))
- API Platform `#[ApiResource]` resources are a first-class attack surface, with a dedicated pre-scan bucket, chunking slot and attacker-skill block ([#105](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/105))
- Symfony UX Live Components are a first-class attack surface, with a dedicated pre-scan bucket, chunking slot and attacker-skill block ([#106](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/106))
- Findings carry a CWE reference next to the OWASP mapping, shown in every report format and tagged `external/cwe/cwe-*` in SARIF ([#127](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/127))
- OWASP references point at the Top 10:2025 edition instead of 2021 ([#98](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/98))
- `audit:diff` compares two JSON reports and lists new, fixed and persisting findings by fingerprint ([#126](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/126))
- Each finding in JSON output carries its stable `SSA-` `fingerprint`, the hash behind baselines and SARIF `partialFingerprints` ([#126](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/126))
- `--format junit` renders findings as JUnit XML for CI test panels ([#100](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/100))
- `--format github` renders findings as GitHub Actions annotations shown inline on a pull request's Files Changed view ([#122](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/122))
- `audit:run --show-scanned` lists the exact files an audit would ingest without calling the LLM ([#87](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/87))
- `security.yaml` is parsed with `symfony/yaml` instead of single-line regexes, so the access-control map the attacker reasons over is complete ([#104](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/104))
- Committed dotenv files in the project root are part of the default scan surface, with deterministic secret markers ([#99](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/99))
- Baselined findings skip the reviewer entirely, and the baseline file is human-readable ([#103](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/103))
- SARIF output marks baselined findings as suppressed instead of dropping them ([#123](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/123))
- The auditor runs as a standalone native executable configured once at the user level, with a PowerShell installer (`install.ps1`) beside the POSIX one ([#91](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/91))
- `bin/console audit` is a shorthand for `audit:run` in the bundle ([#91](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/91))
- LLM pricing comes from the daily `symfony/models-dev` catalog instead of a hand-maintained price table; `audit:run` warns up front about an unpriced model and refuses a budgeted run whose cost it cannot enforce ([#89](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/89))
- Prompt-cache traffic is priced from each provider's real per-model cache rates instead of Anthropic-only multipliers ([#89](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/89))
- The reviewer phase streams a live verdict line per finding, ending the apparent freeze during long reviews ([#78](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/78))
- Symlinked files are no longer followed into the LLM prompt by the project scan ([#134](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/134))

### Deprecations 💀

- `Vulnerability::create()`, `SymfonyMapping::create()` and `LLMResponse::create()` are deprecated, use the `of()` factories instead ([#78](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/78))

### Bugfixes 🐛

- `.xml` config files and non-PHP files under `/Webhook/` or `/MessageHandler/` are classified correctly ([#121](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/121))
- Lean mode (`fast` profile) no longer drops files holding a real sink the code slicer would keep: the pre-scanner now recognises `#[ApiResource]` and `#[AsLiveComponent]` actions reading `$request`, `#[AsEventListener]` listeners, `DenormalizerInterface` classes and dynamic `include` / `require` ([#131](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/131), [#134](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/134))
- Lean mode also keeps files using the modern `$request->` accessors, `Process::fromShellCommandline()`, Twig `createTemplate()`, list-form wildcard CORS, the Messenger `native_php_serializer` transport, DBAL `fetch*` / `iterate*` one-shot queries and `DOMDocument::loadXML()` / `simplexml_load_file()` ([#131](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/131), [#134](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/134))
- Pre-scan custom patterns with the DOTALL (`s`) modifier now match across lines ([#109](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/109))
- A signature compare split across lines is flagged as non-constant-time, in either operand order ([#116](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/116))
- Pre-scan markers match `supports()` returning `null` after an earlier guard, and dynamic `orderBy` / `redirect` / `submit` ([#131](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/131), [#134](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/134))
- Pre-scan markers catch bare column-0 or tab-indented `include` / `require` / `exec` ([#131](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/131), [#134](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/134))
- Route and security parsing report the truth to the attacker: `#[Route(methods: 'DELETE')]` single-string form, `#[Route(name:)]`, name-keyed `access_control` rules, invokable `#[AsController]` services and deliberately public `access_control` routes ([#104](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/104), [#131](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/131), [#134](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/134))
- `#[IsGranted]` is read with `attribute` in any argument position, and voters using `in_array($attribute, [self::EDIT])` are understood ([#134](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/134))
- The code slicer keeps multi-line method signatures and attribute argument lists, no longer desyncs on heredoc-terminated calls and retains bare `include` / `require` statements ([#134](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/134))
- Report renderers no longer crash or pass attacker-influenced text through as terminal markup, ANSI, bidi or Markdown injection, across console, HTML, SARIF, JUnit, GitHub-annotation and Markdown output ([#110](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/110), [#131](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/131), [#134](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/134))
- Accented text no longer corrupts at console wrap points, SARIF rules shared by several categories are named deterministically and JUnit output always re-parses ([#110](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/110), [#131](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/131))
- Findings recorded before a mid-run budget or provider abort are kept, including attacker candidates, reviewer verdicts from all five analyzers and synthesized PoCs, and the partial report still applies the finding-type filter and baseline suppression ([#131](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/131), [#134](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/134))
- A `record_vulnerability` call without `confidence` is dropped instead of skipping the confidence floor, and a dropped finding is logged ([#131](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/131), [#134](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/134))
- LLM retry follows the provider: a `Retry-After` HTTP date is honored, jitter cannot undercut the requested wait, a 529 overloaded response is transient, a misconfigured `retry.max_attempts` cannot wedge the run and a hostile `Retry-After` cannot bypass the safety ceiling ([#115](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/115), [#134](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/134))
- Concurrent LLM calls no longer corrupt the rate limiter's token accounting ([#113](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/113))
- Concurrent tool-using conversations retry a transient failure that happens after a tool already ran, instead of abandoning the conversation as empty ([#120](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/120))
- Cache keys invalidate correctly: the attacker cache key folds in code slicing, static pre-scan and tool toggles, and an escalation run no longer poisons the primary attacker's cache ([#114](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/114), [#131](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/131), [#134](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/134))
- The reviewer verdict cache keys on the structured-collection mode, and the advisory cache honors its TTL and `cache.enabled` ([#134](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/134))
- `audit.budget.max_cost_usd` is validated at boot, `--since` resolves paths in a monorepo subdirectory and no longer drops dotfiles or non-ASCII names, and machine-readable output goes to the correct stream ([#108](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/108), [#131](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/131), [#134](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/134))
- The CI-failure message reflects the actual `--fail-on` threshold ([#131](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/131), [#134](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/134))
- `audit.tools_enabled` and `audit.escalation.enabled` behave as documented, and enabling escalation no longer crashes the container ([#117](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/117), [#131](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/131))
- Bedrock-qualified Claude model IDs use the right token ratio, the `--dry-run` estimate sums per-file token counts, and non-transient status codes embedded as digit substrings are no longer misclassified as fatal ([#111](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/111), [#131](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/131), [#134](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/134))
- A reviewer-cache lookup no longer crashes the run on non-UTF-8 bytes in a finding, the standalone binary emits a clean CLI error when `HOME` and the XDG variables are absent, a stray non-object JSON payload in a batched reviewer response is rejected per finding, and `composer audit` targets the audited project ([#131](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/131), [#134](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/134))
- Three `VulnerabilityType` CWE and OWASP mappings are corrected against MITRE CWE 4.20 and OWASP Top 10:2025 ([#131](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/131))

### Core 🧱

- The secret scrubber no longer leaks credentials into the LLM prompt: unquoted config values, credential variables with the keyword in the middle (`DB_TOKEN_STAGING`), the `api_token` key and the line after an empty-valued credential key are all redacted ([#112](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/112), [#134](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/134))
- The install scripts fail closed on checksum verification ([#91](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/91))
- `AuditBudget::forCost()` and `AuditBudget::forBoth()` reject a non-finite (`+INF`) cost cap instead of silently disabling the budget ([#134](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/134))
- `StaticPricingProvider` and its hand-maintained 68-model `PRICES` constant are removed in favor of the `symfony/models-dev` catalog, as is the unused `AuditPresenterInterface::baselineApplied()` (both `@internal`) ([#89](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/89), [#130](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/130))
- `CacheAwarePricingProviderInterface` is a new Domain port for cache-aware pricing ([#89](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/89))
- `Vulnerability::of()`, `SymfonyMapping::of()` and `LLMResponse::of()` replace the wide positional `create()` signatures, with new domain exceptions `InvalidCodeLocationException` and `InvalidVulnerabilityClassificationException` ([#78](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/78))
- Every raw SPL exception thrown from production code is replaced with a project-defined exception ([#134](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/134))
- `ProjectFile` type detection is a single source of truth, so `fileType()` and the `is*()` predicates can no longer disagree ([#121](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/121))
- Report rendering is split into one class per format behind `ReportRendererInterface`, and prompt building into separate attacker and reviewer builders ([#100](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/100), [#107](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/107))
- The structured-collection wiring shared by five analyzers is extracted into one collaborator per domain ([#124](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/124))
- Constructor ports that DI always resolves are now required instead of silently falling back to a `Null*` default ([#125](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/125))

## [1.12.0] — 2026-06-16 — Spotlight

### New Features ✨

- `audit:run` streams each finding the instant the attacker records it (e.g. `⚔ 🟠 HIGH sql_injection — src/Controller/UserController.php:42`), opens the audit with an attack-surface overview listing only non-empty categories, and closes each iteration with a reviewer tally (`✓ Reviewed: 5 validated, 1 rejected`) ([#70](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/70))
- Slow and local-model runs no longer look frozen: the progress bar reads `⏳ querying model · chunk 2/5` while a call is in flight and each chunk prints its wall time when it returns (`✓ chunk 2/5 analyzed (47s)`) ([#70](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/70))
- Non-interactive output (CI logs, pipes, redirected files) gets plain append-only progress lines instead of progress-bar redraws, while a decorated terminal keeps the animated bar with an elapsed-time counter and a severity-colored findings feed above it; `--format=json|sarif` on stdout stays silent ([#70](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/70))
- `audit:run` prints the resolved absolute project directory in its header and report (instead of `.`), and the long-run heads-up is now a dim one-line message instead of a boxed `[NOTE]` ([#70](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/70))
- Reports link back to the project: the HTML footer is now a hyperlink, the Markdown report gains a `Generated by` footer and the console header prints the project URL (JSON and SARIF are unchanged) ([#73](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/73))
- The `--dry-run` "no pricing data" notice states that `$0.00` is correct for a local or self-hosted model (Ollama, LM Studio) and only flags a typo or an unlisted model as the problem case ([#72](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/72))

### Bugfixes 🐛

- Symfony component detection: controllers, voters, forms, entities and repositories are now recognized by directory (`/Controller/`, `/Voter/`, `/Repository/`, `/Entity/`, `/Entities/`, `/Form/` with a `Type.php` suffix) and by content, not only by filename suffix, so invokable-style controllers get route, access-control and form analysis and are counted in the overview ([#70](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/70))
- Concurrent tool-using conversations: a timeout or `5xx` that happens after a tool already ran is now retried like every other call instead of discarding the conversation as empty ([#70](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/70))

### Core 🧱

- The minimum `symfony/ai-bundle` requirement moves from `^0.9` to `^0.10`; projects pinning `^0.9` must allow `^0.10` to upgrade ([#71](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/71))
- The progress reporter port gains the `audit.started`, `review.completed`, `attacker.finding.recorded` and `attacker.chunk.completed` events, additive to the ones shipped in 1.11.0 ([#70](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/70))

## [1.11.0] — 2026-06-15 — Tracer

### New Features ✨

- `audit.fail_on` and `audit:run --fail-on=<level>` (`safe`, `low`, `medium`, `high` or `critical`) set the risk level at which the run exits `1`, so a pull request can fail on HIGH, MEDIUM or LOW findings; the default stays `critical`, so existing exit codes are unchanged, and it is planned to become `high` in the next major (pin it explicitly to be immune) ([#65](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/65))
- `audit.excluded_types` drops findings of the listed vulnerability types from the report, the exit code and any generated baseline, and `audit.included_types` is an allowlist that keeps only the listed types (exclusions win); both default to `[]` and are validated against the vulnerability types ([#65](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/65))
- SARIF results carry a stable `partialFingerprints` value (`symfonySecurityAuditor/v1`, the same fingerprint baselines use) so GitHub Code Scanning tracks findings across runs, and each rule's `helpUri` points to its own OWASP Top 10 2021 category page ([#66](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/66))
- `audit:run --format=markdown` renders a GitHub-flavored report (heading, severity summary table and one section per finding) for pull-request comments and job summaries ([#66](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/66))
- The attacker traces each attacker-controlled value from source to sink and checks for a neutralizing guard before reporting, sweeps the STRIDE categories per entry point, and weights severity by reachability and exposure ([#68](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/68))

### Bugfixes 🐛

- OWASP mapping: `authenticator_bypass` now maps to `A07:2021 - Identification and Authentication Failures` and `missing_signature_verification` to `A08:2021 - Software and Data Integrity Failures`, which changes the SARIF `ruleId` and `helpUri` of findings of those two types ([#66](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/66))

### Core 🧱

- Cached attacker answers refresh once after upgrading ([#68](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/68))

## [1.10.1] — 2026-06-15 — Encore

### Core 🧱

- Packaging-only republish of 1.10.0 — Lookout, whose tag Packagist had indexed on an incomplete commit and could not move; there are no source changes, only the config-schema URL and GitHub Action `uses:` pins move from `1.10.0` to `1.10.1` ([#64](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/64))

## [1.10.0] — 2026-06-15 — Lookout

### New Features ✨

- `audit:run --format=html` renders a self-contained report (inline CSS, severity-colored summary table, one card per finding) with every dynamic value HTML-escaped, suitable as a CI artifact ([#59](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/59))
- Baseline suppression of accepted findings: `audit:run --generate-baseline=<file>` writes the fingerprint of every current finding and exits `0`, and `--baseline=<file>` (or `audit.baseline`) drops the listed findings from the report and the exit code so only new findings fail CI; fingerprints ignore line numbers, and a malformed baseline file is refused ([#59](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/59))
- A reusable composite GitHub Action (`uses: vinceamstoutz/symfony-security-auditor@v1`) sets up PHP, installs dependencies and runs `audit:run`, with inputs `project-path`, `format`, `output`, `baseline`, `generate-baseline`, `since`, `extra-args`, `php-version`, `setup-php`, `install-dependencies` and `working-directory` ([#59](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/59))
- The bundle ships a JSON Schema that gives editors that use the YAML Language Server key completion, type checking and inline docs for the `symfony_security_auditor` bundle configuration file, enabled by a `# yaml-language-server: $schema=…` modeline ([#59](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/59))

### Bugfixes 🐛

- Cost reporting: corrected stale Mistral list prices (`mistral-medium-latest` and `mistral-medium-2604` `$0.40/$2.00`, `mistral-small-latest` and `mistral-small-2603` `$0.15/$0.60`, `ministral-3b-2512` `$0.04/$0.04`, `ministral-8b-2512` `$0.10/$0.10` per million tokens), which had inflated the estimated and actual cost of those models ([#61](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/61))

### Performance Improvements 🚀

- The reviewer-verdict cache now covers batched reviews (`audit.reviewer_batch_size` > 1): cached verdicts are served first and only the misses go to the LLM, and the pre-flight notice that batching disables the cache is removed ([#58](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/58))

### Core 🧱

- The pre-flight token estimator is now one implementation per LLM provider, tagged `symfony_security_auditor.token_estimator`, with unchanged estimates so `--dry-run` costs stay the same ([#61](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/61))
- The model hints in the Composer `suggest` block are refreshed ([#57](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/57))

## [1.9.0] — 2026-06-12 — Slipstream

### New Features ✨

- The default `model` is now `claude-opus-4-8` at the same `$5/$25` per-MTok price; pin `model: 'claude-opus-4-7'` to keep the previous default ([#56](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/56))
- `profile` (`fast`, `balanced` default or `thorough`) is a one-knob preset for `audit.max_iterations`, `audit.static_prescan.lean_mode`, `audit.code_slicing.enabled`, `audit.poc_synthesis.enabled` and `audit.reviewer_max_concurrent`; it only fills keys you left unset, `balanced` equals configuring nothing, `fast` runs one iteration with code slicing and four concurrent reviews, and `thorough` adds PoC synthesis ([#56](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/56))
- `audit.reviewer_structured_collection` (default `true`) records reviewer verdicts through a schema-enforced `record_review` tool so a malformed verdict cannot occur; `reviewer_tools_enabled: true` keeps the JSON path, `reviewer_max_concurrent` > 1 composes with it on async platforms, and `false` forces JSON-array output for models without tool use ([#48](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/48), [#56](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/56))
- The reviewer concurrently reviews findings through `record_review` when `reviewer_max_concurrent` > 1, via the new `ToolBatchCapableLLMClientInterface` port, and falls back to the JSON path on clients without it ([#56](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/56))
- The attacker is told which findings the reviewer already rejected and is instructed not to re-report those locations, so later iterations stop re-reporting them ([#44](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/44))
- The reviewer no longer drops real findings that are hard to prove: it rejects only when it can name a mitigating control or the pattern is absent, and otherwise accepts with a downgraded severity (down to `info`) and records the missing evidence in `reviewer_notes` ([#42](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/42))
- The attacker's route access-control map tags a route covered by a `security.yaml` `access_control` rule as `COVERED_BY access_control[…]` with its roles, instead of `LACKS_ACCESS_CHECK`, removing a class of false `broken_access_control` findings ([#47](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/47))
- Reports list vulnerabilities most-severe-first in the console, the JSON `vulnerabilities` array and the SARIF `results` array (ties keep discovery order) ([#54](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/54))
- The console shows live audit-stage progress (`audit · iteration 1/3 · attacker chunk 4/12`, `audit · iteration 1/3 · reviewing 4 finding(s)`) and a long-run notice above the progress bar; `--format=json|sarif` on stdout stays clean ([#55](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/55))
- Prompt-cache tokens are priced into the audit cost: cache reads and writes now count in budget enforcement and `estimated_cost_usd` (Claude models at `0.1x` for reads and `1.25x` for writes, other models at the plain input rate) ([#50](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/50))
- `audit:run` prints pre-flight stderr notices when escalation's `audit.escalation.cheap_model` resolves to the attacker model (no saving), when `reviewer_max_concurrent` > 1 is combined with `reviewer_tools_enabled: true`, when `attacker_max_concurrent` > 1 lacks the structured-collection-without-tools mode it needs, and when batched reviews disable the reviewer cache ([#56](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/56))
- The `--dry-run` output states that real runs typically cost less, since the estimate excludes provider prompt-cache discounts and warm caches ([#56](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/56))

### Bugfixes 🐛

- The attacker prompt no longer asks for a JSON array in the default structured-collection mode, where it contradicted the `record_vulnerability` instruction and could produce discarded output ([#41](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/41))
- The reviewer can relabel a finding to `over_permissive_serializer_group`, the one type it could not previously correct to ([#41](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/41))
- `audit:run --dry-run` no longer undercounts tokens for `claude-fable-5` and `claude-mythos-5`, whose new tokenizer emits about 30% more tokens, so the estimated cost is no longer about a third too low ([#43](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/43))

### Performance Improvements 🚀

- `audit.attacker_max_concurrent` analyzes cache-miss attacker chunks concurrently when the platform has an async transport (`fast` profile: `4`, `balanced` and `thorough`: `1`), with identical results to the sequential path; it is ignored when `audit.tools_enabled` is on or `audit.structured_collection` is off ([#56](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/56))
- `audit.stable_system_prompt` (default `true`) sends the full attacker skill set on every chunk so the system prompt is byte-identical and provider prompt caching (Anthropic, OpenAI, Gemini, DeepSeek) reads it after the first call; set it to `false` for relevance-only skills and a smaller prompt on providers without caching ([#46](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/46), [#56](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/56))
- Reviewer verdicts are cached across runs in a `reviewer` folder under `cache.dir` when `cache.enabled` is on, so an unchanged finding on unchanged code skips the reviewer LLM call; `--no-cache` bypasses it ([#49](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/49))
- The attacker cache now also covers iterations 2 and later, where chunks carrying prior validated or rejected findings used to bypass it ([#56](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/56))

### Core 🧱

- Cached attacker answers refresh once after upgrading ([#41](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/41), [#47](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/47), [#56](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/56))

## [1.8.0] — 2026-06-11 — Fable

### New Features ✨

- Cost estimates cover Claude Fable 5 (`claude-fable-5`, `$10/$50` per million input/output tokens), so `audit:run --dry-run` reports a real figure instead of `$0.00` ([#38](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/38))

### Bugfixes 🐛

- Cost estimator: corrected stale list prices for `mistral-small-latest` and `mistral-small-2603` (`$0.10/$0.30`) and `deepseek-v4-pro` (`$0.435/$0.87`) per million input/output tokens ([#38](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/38))

## [1.7.2] — 2026-06-07 — Lighthouse

### Bugfixes 🐛

- `audit:run --dry-run`: warns on stderr, also for `--format=json` and `--format=sarif` without polluting stdout, when a configured `model`, `attacker_model` or `reviewer_model` has no pricing data, instead of silently reporting `$0.00` ([#37](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/37))

## [1.7.1] — 2026-06-04 — Parachute

### Bugfixes 🐛

- Console commands such as `cache:clear` and `cache:warmup` no longer fail when no AI platform is configured (a fresh skeleton, where the `symfony/ai-bundle` recipe comments every platform out); only the first LLM call raises the new `MissingAiPlatformException` with an actionable message ([#35](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/35))

## [1.7.0] — 2026-05-29 — Polyglot

### New Features ✨

- Cost estimates cover every commercial platform shipped by `symfony/ai` (Anthropic including `claude-opus-4-8`, OpenAI including the GPT-5 family, Google Gemini including `gemini-3.1-pro-preview`, Mistral, Cohere, DeepSeek, Perplexity and Cerebras); prompt-size-tiered models are priced at their base tier and self-hosted platforms stay unpriced ([#34](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/34))

### Deprecations 💀

- `cache.prompt_caching` no longer has any effect and emits a deprecation notice when set; set `cache_retention` (`none`, `short` or `long`) on the `anthropic` platform in `ai.yaml` instead (OpenAI and Gemini cache automatically); the key stays accepted until the next major ([#34](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/34))

### Bugfixes 🐛

- Non-Anthropic providers no longer crash on Anthropic-only options: `cache_control` and `max_tokens` made Gemini runs abort and `max_tokens` broke the OpenAI Responses bridge, so `max_tokens` and `response_format` are now sent to Claude models only and other providers use their native output limit ([#34](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/34))

## [1.6.4] — 2026-05-29 — Hush

### New Features ✨

- The console report no longer prints the `Cost` line and per-role cost breakdown after a real run, since it is only a rough estimate that diverges from provider invoices; the token line, the `--dry-run` estimate and `estimated_cost_usd` in the JSON and SARIF outputs are unchanged ([#33](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/33))

### Bugfixes 🐛

- `Tool-using loop ended with empty content response`: no longer logged at `warning` level when the attacker ends a chunk with an empty answer after recording findings through tool calls, which is the normal end of a structured-collection run; it is logged at `debug`, and the warning stays for an empty answer on the very first call ([#33](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/33))

## [1.6.3] — 2026-05-28 — Watertight

### Bugfixes 🐛

- Secret scrubbing: credentials embedded in connection strings such as `DATABASE_URL=postgres://user:s3cret@host` or `REDIS_URL=redis://:pass@host` are now redacted before the content is sent to the LLM provider, keeping the scheme and host (`postgres://***REDACTED:connection_uri***@host`) ([#32](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/32))

## [1.6.2] — 2026-05-28 — Headroom

### New Features ✨

- Add the `max_output_tokens` configuration key (default `4096`), which sets the output-token limit of every LLM call ([#31](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/31))
- Add `attacker_max_output_tokens` and `reviewer_max_output_tokens` to override that limit per role, so the attacker can get more room (for example `8192`) than the reviewer (for example `2048`); both fall back to `max_output_tokens` when unset ([#31](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/31))

### Bugfixes 🐛

- LLM calls are no longer cut off at about 1000 output tokens: the bundle now sets `max_tokens` explicitly, where the Anthropic bridge's default truncated findings mid-way and produced `Tool-using loop ended with empty content response` warnings ([#31](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/31))

### Core 🧱

- Audits now get complete answers, so expect fewer tool-loop iterations per chunk and a higher output-token spend per call; when you raise `max_output_tokens`, raise `audit.rate_limit.output_tokens_per_minute` too, since the default `4096` with an `80_000` ceiling trips the limiter after about 19 calls per minute ([#31](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/31))

## [1.6.1] — 2026-05-28 — Soft Landing

### Bugfixes 🐛

- An LLM response with no content (refusal-style stop, content filter, prompt-cache quirk) no longer aborts the audit with `Response does not contain any content.`: the chunk counts as analyzed, findings already recorded through tool calls are kept, and the audit goes on ([#30](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/30))

## [1.6.0] — 2026-05-28 — Sentinel

### New Features ✨

- Collect the attacker's findings through a `record_vulnerability` tool call whose input is a strict JSON Schema validated by the provider, so bare-string and wrapper-object drift in the model output cannot happen with Anthropic, OpenAI, Mistral and tool-capable Ollama models ([#29](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/29))
- Add `audit.structured_collection` (default `true`); existing audits switch to tool-call collection on upgrade, and `false` keeps the JSON-array path for models without tool-use support ([#29](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/29))
- Tighten the JSON-array prompt used when `audit.structured_collection` is `false`: it forbids non-object array elements, environment-keyed wrapper objects and bare environment-name strings, which were previously dropped silently ([#29](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/29))

### Core 🧱

- Add `VulnerabilityCollector` and `RecordVulnerabilityToolFactoryInterface`, the seam that lets the attacker build a fresh collector and tool per chunk without importing Infrastructure types ([#29](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/29))

## [1.5.0] — 2026-05-28 — Cartographer

### New Features ✨

- Map every controller route with its `#[IsGranted]` attributes and `denyAccessUnlessGranted()` calls, and flag the routes that check nothing ([#28](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/28))
- Match each `#[IsGranted('ATTR', $subject)]` against the voters that actually accept that attribute and subject, and report a `missing_voter` finding when none does ([#28](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/28))
- Map every `createForm(SomeFormType::class)` call to its controller, so the audit reviews mass-assignment and CSRF exposure per form ([#28](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/28))
- Add the `over_permissive_serializer_group` finding (OWASP A05:2021): privileged fields such as `roles` or `isAdmin` in write groups, and sensitive fields in read groups, on `#[Groups(...)]` and `@Groups({...})` ([#28](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/28))
- Count the findings the model proposed but the auditor dropped as malformed, by reason, in the `Attacker agent complete` log line (`total_dropped_entries`, `dropped_by_reason`) ([#28](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/28))
- Reject nonsensical model output (empty file paths, oversized descriptions) before it reaches the report ([#28](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/28))
- Warn on stderr when `scan.secret_scrubbing.enabled` is `false`, since file contents then go to the LLM provider as they are; the warning never pollutes `--format=json|sarif` output ([#28](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/28))

### Core 🧱

- Cached attacker answers refresh once after upgrading, because the attacker prompt and the pre-scanner patterns changed ([#28](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/28))
- `nikic/php-parser` `^5.3` is now a direct dependency ([#28](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/28))
- Custom agents that build `VulnerabilityFactory` by hand must now pass a `ValidatorInterface` (the class is `@internal`) ([#28](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/28))

## [1.4.0] — 2026-05-27 — Bloodhound

### New Features ✨

- Cover the modern Symfony 7.x and 8.x attack surface: new detectors and attacker checks for Authenticators, Messenger handlers, Webhook consumers, EventSubscribers, Normalizers and Scheduler tasks, plus `#[MapRequestPayload]`, Twig and Live Components, `html_sanitizer`, mailer header injection, cache poisoning, `RateLimiterFactory` scope confusion and `HttpClient` redirect-host bypass ([#26](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/26))
- Add the finding types `missing_signature_verification`, `messenger_handler_unsafe`, `missing_rate_limiting`, `cache_poisoning`, `mailer_header_injection`, `webhook_replay` and `authenticator_bypass` ([#26](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/26))
- Tag files with about 30 deterministic risk markers (unserialize, shell exec, `|raw`, `csrf_protection: false`, hardcoded secrets, Doctrine string concatenation, …) before the LLM runs, at no token cost; `audit.static_prescan.enabled` (default `true`) switches it and `audit.static_prescan.lean_mode` (default `false`) drops marker-free files to cut token spend ([#26](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/26))
- Add `scan.custom_risk_patterns` to merge project-specific regex markers into the pre-scanner, keyed by file type ([#26](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/26))
- Add `audit.chunking.strategy` (default `feature`), which sends a controller with its entity, repository, form, voter and templates in one chunk so the LLM can follow data flow across files; `type` restores the previous priority-window chunking ([#26](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/26))
- Pass the already validated findings to iterations 2 and later, so the attacker generalizes patterns to uncovered files instead of rediscovering the same bugs ([#26](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/26))
- Add `audit.reviewer_tools_enabled` (default `false`) to give the reviewer the same `read_file`, `grep`, `list_files` and `lookup_advisory` tools as the attacker, capped by `audit.reviewer_max_tool_iterations` ([#26](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/26))
- Add `audit.poc_synthesis.enabled` (default `false`) and `audit.poc_synthesis.severity_floor` (default `high`) to generate a copy-pasteable reproduction (curl, console invocation, payload) for validated findings, exposed in the new `synthesized_poc` report field ([#26](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/26))
- Add `audit.code_slicing.enabled` (default `false`) and `audit.code_slicing.min_lines_before_slicing` (default `80`) to trim large PHP files to their security-relevant lines while keeping line numbers accurate; the new `CodeSlicerInterface` port has `RegexCodeSlicer` and `NullCodeSlicer` implementations ([#26](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/26))
- Add `audit:run --since=<ref>` to audit only the files changed against a git ref, committed or not, for fast pull-request scans ([#26](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/26))
- Add `audit.escalation.enabled` (default `false`) and `audit.escalation.cheap_model`: a cheap model sweeps first and the expensive model only re-analyses the files it flagged, with the cheap findings as context ([#26](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/26))
- Add `audit.reviewer_max_concurrent` (default `1`) to review findings concurrently when the reviewer runs one finding per call with tools off, shortening the reviewer phase ([#26](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/26))
- Cache attacker answers per pre-scanner version and `scan.custom_risk_patterns` hash, so changing custom patterns invalidates stale entries, and keep empty LLM responses as negative-cache entries ([#26](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/26))
- Default file chunking is now `feature`; set `audit.chunking.strategy: type` to restore the previous behaviour ([#26](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/26))

### Core 🧱

- Cached attacker answers refresh once after upgrading, because the attacker prompt changed (version 4) ([#26](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/26))
- Add a `ProjectFileType` enum for the file-type vocabulary; `ProjectFile::type()` still returns the string value and `ProjectFile::fileType()` returns the typed case ([#26](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/26))
- `symfony/string` is now a runtime dependency, and `symfony/filesystem` and `symfony/string` are used outside the Domain layer ([#26](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/26))
- `AttackerAgent::analyze()` takes an immutable `AttackerAnalysisRequest` instead of five positional parameters (the interface is `@internal`) ([#26](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/26))

## [1.3.3] — 2026-05-26 — Mesh

### New Features ✨

- The skipped-entry warning for a malformed model answer now carries an `entry_preview` field (the first 120 bytes of a string, `null` otherwise), so you can see what the model emitted without enabling debug logging ([#25](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/25))

### Bugfixes 🐛

- The attacker is now told never to emit bare strings, numbers, booleans or `null` as array elements and to return `[]` instead of prose, so audits of vulnerability-free projects no longer log `Skipping non-array vulnerability entry from LLM` warnings ([#25](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/25))
- Stray non-array entries from a chatty model are no longer written to the attacker cache, so the same warning no longer fires again on every cache hit ([#25](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/25))

### Core 🧱

- Cached attacker answers refresh once after upgrading, because the attacker prompt changed (version 3) ([#25](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/25))

## [1.3.2] — 2026-05-26 — Sieve

### New Features ✨

- `audit:run` shows a live console progress bar over its three stages (Ingestion, Mapping, Audit), hidden for `--format=json|sarif` piped to stdout and for `--dry-run` ([#24](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/24))

### Bugfixes 🐛

- `audit:run --dry-run` no longer prints `RISK LEVEL: SAFE` and `Audit complete`, which implied an audit had run: it shows the estimated tokens and cost followed by `Dry run complete.`; with `--format=json|sarif --output=<file>` the report is still written to disk ([#24](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/24))
- A stray scalar (string, number or `null`) among the vulnerability entries of a model answer no longer aborts the whole chunk: it is dropped with a `warning` log ([#19](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/19))
- Secret scrubbing no longer redacts Symfony parameter references (`%env(ANTHROPIC_API_KEY)%`, `%kernel.secret%`) or shell expansions (`$NAME`, `${NAME}`) in credentialed assignments, which the attacker used to report as a critical hardcoded credential; literal secrets are still redacted ([#20](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/20))
- The attacker is told its tool-call budget per chunk is finite and to answer with the final JSON, or `[]` when the initial scan finds nothing, instead of exhausting `max_tool_iterations` without ever answering ([#22](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/22))
- When a model wraps its JSON answer in prose that contains brackets such as `recommendation.contents[locale]`, the answer is now recovered by trying every JSON block instead of giving up at the first bracket ([#21](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/21))

### Core 🧱

- Cached attacker answers refresh once after upgrading, because the attacker prompt changed (version 2) ([#22](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/22))
- Magic strings for progress events, agent roles, built-in stage names and secret-pattern labels are now `@internal` enums; the values on the wire are unchanged ([#24](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/24))

## [1.3.1] — 2026-05-26 — Watertight

### Core 🧱

- Test-suite only release: no production code change ([#18](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/18))

## [1.3.0] — 2026-05-26 — Bonsaï

### New Features ✨

- Add `scan.included_paths` (default `['src', 'config', 'templates', 'public/index.php']`), the only setting that scopes the audit: only the listed directories and files are inspected and everything else is skipped; a `No included paths exist in project` warning is logged and nothing is scanned when none exists ([#17](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/17))

### Breaking Changes 💥

- `scan.excluded_dirs` is removed; narrow `scan.included_paths` to the sub-directories you want audited instead ([#17](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/17))
- The `ProjectFileScanner` constructor parameter `additionalExcludedDirs` and its `HARD_EXCLUDED_DIRS` list are removed, since the scanner no longer walks into `vendor/` or `node_modules/` ([#17](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/17))

### Bugfixes 🐛

- `scan.max_file_size_kb` now means kibibytes (1024 bytes) for both scanned directories and explicitly listed files, which used to disagree for files between `1000 * N` and `1024 * N` bytes ([#17](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/17))
- A model answer wrapped in conversational prose around a balanced JSON block is now recovered instead of dropping the whole chunk's findings with `JsonException: Syntax error` ([#17](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/17))
- Attacker and reviewer parse-failure error logs now include a 512-byte `content_preview` of the LLM response ([#17](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/17))

## [1.2.1] — 2026-05-25 — High Temperature

### Bugfixes 🐛

- `temperature` is no longer sent to the provider unless you configured one, so reasoning-only models such as GPT-5 no longer fail with a `temperature does not support` error before any chunk is analyzed; a configured value is still forwarded unchanged ([#16](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/16))

## [1.2.0] — 2026-05-25

### New Features ✨

- `audit:run --path=<subdir>` (repeatable, shortcut `-p`) restricts the scan to one or several project-relative subdirectories while the project root still provides `composer.lock` for advisory lookups, which suits monorepos where only one app needs auditing ([#15](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/15))
- `audit:run --no-cache` bypasses the attacker cache for the run: every chunk calls the LLM, and nothing is read from or written to the cache, leaving existing entries on disk untouched ([#15](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/15))
- `ProgressReporterInterface` lets a host follow a run through `pipeline.started`, `stage.started`, `stage.completed` and `pipeline.completed` events, with the silent `NullProgressReporter` as default and a `LoggerProgressReporter` ready to use ([#15](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/15))
- Token estimates cover Mistral / Codestral, Llama (`llama-*`, `llama3*`, `llama4*`, `meta-llama/*`) and DeepSeek models, and an optional `$charsPerTokenByPrefix` map on `CharacterBasedTokenEstimator` adds or overrides ratios for fine-tuned or self-hosted models ([#15](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/15))
- `audit:run --dry-run` reports the cost per role, with the attacker model and the reviewer model priced separately; `AuditCost` exposes it through `byRole()` and `by_role` in the JSON report ([#15](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/15))
- `audit.rate_limit.requests_per_minute`, `audit.rate_limit.input_tokens_per_minute` and `audit.rate_limit.output_tokens_per_minute` (each `int|null`, default `null`) make the audit wait ahead of time to stay inside the provider's per-minute quota; when all three are `null` the previous retry-only behaviour is unchanged, and `RateLimiterInterface` is the port for a custom limiter ([#15](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/15))
- A provider's `Retry-After` hint on a `429` now drives the wait (capped at `300000` ms by default) and pauses the chunks scheduled after it, instead of letting them hit the provider all at once ([#15](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/15))

### Bugfixes 🐛

- `audit:run` no longer crashes on the first chunk that draws a `429`, and rate-limited responses now go through retry and backoff, because a response body that fails while being read is retried instead of escaping the retry logic ([#15](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/15))

### Performance Improvements 🚀

- `composer audit` results are cached on disk across runs, keyed by the hash of `composer.lock`, so CI re-runs and repeated `--dry-run` no longer spawn composer again; a project without a lockfile runs the audit every time ([#15](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/15))

### Core 🧱

- Cached attacker answers refresh once after upgrading, and switching the attacker model or the prompt version invalidates them from now on ([#15](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/15))
- `phpunit/phpunit` moves from `^11.5` to `^12.5` in the dev dependencies (PHP `>=8.3` unchanged), and `psr/clock` becomes a runtime dependency ([#15](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/15))
- The README opens with a 30-second quick start ([#15](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/15))

## [1.1.1] — 2026-05-24

### Core 🧱

- The mutation-testing gate now covers the debug log of a rejected review, with no change to the audit itself ([#13](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/13))

## [1.1.0] — 2026-05-24

### New Features ✨

- The reviewer can correct a finding's vulnerability type: its `corrected_type` answer is validated against the known types and applied through `Vulnerability::withCorrectedType()`, which keeps the original `id`, while an invalid value is logged and ignored ([#12](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/12))
- `symfony_security_auditor.provider_json_mode` (boolean, default `false`) sends `response_format: {type: json_object}` with every LLM call; OpenAI, Mistral and Ollama enforce it, Anthropic and providers without an equivalent ignore it ([#12](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/12))
- Source files reach the attacker as `<file path="…" type="…">` blocks with numbered lines, and the model is told to take `line_start` and `line_end` from those numbers ([#12](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/12))
- The attacker prompt carries a severity rubric, a confidence rubric with a hard `< 0.6` filter threshold, a worked example, and excludes `vendor/`, `var/cache/`, `var/log/`, `.generated.*` and `.cache.*` paths ([#12](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/12))
- Each attack-surface skill block lists the patterns to hunt and the patterns not to flag, and the blocks are emitted in attack-surface priority order inside `<skills role="…">` tags ([#12](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/12))
- The single and batch reviewer prompts share one instruction block and the attacker's severity rubric, include a Symfony false-positive playbook (Doctrine `setParameter()`, default CSRF, `mapped: false` form fields, hardcoded-argv `Process` calls, `_profiler` gated by `when@dev`), and batch answers no longer need to follow the input order ([#12](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/12))

## [1.0.0] — 2026-05-24

### New Features ✨

- A multi-agent audit pipeline (ingestion, mapping, audit) pairs an adversarial attacker agent with a skeptical reviewer agent, for up to 3 iterations and stopping early when no new finding appears ([#9](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/9))
- The LLM backend is provider-agnostic through `symfony/ai`: Anthropic, OpenAI, Azure OpenAI, Google Gemini, Google Vertex AI, AWS Bedrock, DeepSeek, Mistral, Meta Llama and Ollama work by changing only the `ai.yaml` platform configuration ([#9](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/9))
- 32 vulnerability types across 6 OWASP-aligned categories: Injection, Broken Access Control, Logic Flaws, Symfony-specific, Data Exposure and Cryptographic ([#9](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/9))
- `attacker_model` and `reviewer_model` pair a larger model for finding vulnerabilities with a faster, cheaper one for review, such as `claude-opus-4-7` with `claude-haiku-4-5-20251001` ([#9](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/9))
- `audit:run` prints the report as `console`, `json` or `sarif` (SARIF 2.1.0, for GitHub Code Scanning and GitLab Security Dashboard), and `--output` writes JSON or SARIF to a file ([#9](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/9))
- `audit:run --dry-run` estimates tokens and cost without calling the LLM, exits `0` with no findings and a filled `cost` block ([#9](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/9))
- `audit:run` exits `0` for a complete audit (SAFE, LOW, MEDIUM or HIGH), `1` for CRITICAL risk or an invalid project path, and `2` when a token or cost budget is exceeded, in which case a partial report is emitted ([#9](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/9))
- Real token usage (input, output and cached tokens) is recorded from the platform response on every LLM call, and the report carries a `cost` block with total tokens and estimated USD cost ([#9](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/9))
- `audit.budget.max_tokens` and `audit.budget.max_cost_usd` (both `null`, meaning unlimited, by default) abort the audit cleanly with exit code `2` and a partial report once a limit is exceeded ([#9](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/9))
- Every LLM call retries transient errors (HTTP 429, 5xx, network blips) with jittered exponential backoff and fails fast on non-transient ones, tuned by `audit.retry.max_attempts` (3), `audit.retry.initial_delay_ms` (500), `audit.retry.backoff_multiplier` (2.0) and `audit.retry.jitter_ratio` (0.2) ([#9](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/9))
- Credential-shaped strings (AWS, GitHub, Stripe, Slack and Google API keys, JWTs, PEM private keys, env-style assignments) are redacted from file content before it reaches any LLM provider; `scan.secret_scrubbing.enabled` is `true` by default and `scan.secret_scrubbing.additional_patterns` extends it ([#9](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/9))
- The attacker investigates across files with `read_file`, `grep` and `list_files`, and `lookup_advisory` queries known advisories through `composer audit --format=json --locked`, degrading to an empty database and a `warning` log when `composer` or `composer.lock` is missing ([#9](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/9))
- `cache.enabled: true` caches attacker chunks by content hash and skips the LLM call for an identical chunk, and `cache.prompt_caching: true` sends `cache_control: ephemeral` for provider-side prompt caching (about 90% input-token discount on Anthropic, ignored elsewhere) ([#9](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/9))
- The YAML configuration under `symfony_security_auditor:` covers `model`, `attacker_model`, `reviewer_model`, `scan.*` (`excluded_dirs`, `respect_gitignore`, `max_file_size_kb`, `secret_scrubbing.*`), `audit.*` (`max_iterations`, `min_confidence`, `reviewer_batch_size`, `tools_enabled`, `max_tool_iterations`, `budget.*`, `retry.*`) and `cache.*` (`enabled`, `dir`, `prompt_caching`) ([#9](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/9))
- The default model is `claude-opus-4-7` and the default reviewer model is `claude-haiku-4-5-20251001`, replacing the retired `claude-opus-4-5` and `claude-haiku-4-5` ([#9](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/9))
- The pricing table covers `claude-opus-4-7`, `claude-sonnet-4-6`, `claude-haiku-4-5-20251001`, `claude-opus-4-6`, `claude-opus-4-1`, `claude-opus-4`, `claude-sonnet-4`, `gpt-4.1`, `o3`, `o4-mini`, `gemini-2.0-flash` and `mistral-large`, and keeps the retired `claude-opus-4-5` and `claude-haiku-4-5` entries so existing configurations still report cost ([#9](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/9))
- Documentation ships in `docs/`: architecture, configuration, extending, CI, diagrams, FAQ and troubleshooting, plus `docs/versioning.md` with the semantic-versioning policy and the public API surface ([#9](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/9))

### Bugfixes 🐛

- Budget exceptions are rethrown by the attacker and reviewer agents, so a budget overrun now aborts the audit and exits with code `2` ([#9](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/9))
- SARIF `tool.driver.version` is read from the installed Composer metadata instead of a hardcoded value ([#8](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/8))
- Non-transient LLM failures (missing platform configuration, authentication errors, retired model names) abort the audit with exit code `1` and a clear message instead of producing a false-negative SAFE result ([#9](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/9))
- Anthropic Claude 4 Opus pricing is corrected from the Claude 3 Opus rate (`$15.00 / $75.00` per MTok) to `$5.00 / $25.00` per MTok input/output, so cost estimates in CI reports recalculate at the right rate ([#9](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/9))

### Core 🧱

- Requires PHP `^8.3`, Symfony `^7.4 || ^8.0` and `symfony/ai-bundle` `^0.9`, and is tested on PHP 8.3 / 8.4 / 8.5 with Symfony 7.4 / 8.0 / 8.1 ([#9](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/9))
- Strict DDD layering (`Command → Application → Domain ← Infrastructure`) keeps `LLMClientInterface` as the only seam to `symfony/ai`, and the Domain ports (`LLMClientInterface`, `AttackerCacheInterface`, `ProjectFileScannerInterface`, the prompt builder interfaces and the tool classes) live in the `Audit\Domain\Port` namespace ([#9](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/9))
- The bundle settings are read through typed configuration value objects instead of raw arrays ([#9](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/9))
- Every class that is not an extension point is tagged `@internal` ([#8](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/8), [#9](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/9))
- The extension points are `LLMClientInterface`, `AdvisoryDatabaseInterface`, `AttackerPromptBuilderInterface`, `ReviewerPromptBuilderInterface`, `ProjectFileScannerInterface`, `AttackerCacheInterface`, `ToolInterface`, `PipelineInterface` and `StageInterface`, described in `docs/extending.md` ([#9](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/9))
- `AdvisoryDatabaseInterface` moves from `Audit\Infrastructure\Advisory\` to `Audit\Domain\Port\`, so a host that aliases it as a service must update the class name; `ComposerAuditAdvisoryDatabase` and `InMemoryAdvisoryDatabase` keep theirs ([#11](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/11))
- The secret scrubber no longer relies on a temporary error handler around its regular expressions ([#9](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/9))
- The bundle is meant to be registered in the `dev` and `test` environments only ([#9](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/9))

[1.21.0]: https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.21.0
[1.20.1]: https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.20.1
[1.20.0]: https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.20.0
[1.19.1]: https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.19.1
[1.19.0]: https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.19.0
[1.18.0]: https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.18.0
[1.17.0]: https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.17.0
[1.16.0]: https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.16.0
[1.15.0]: https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.15.0
[1.14.0]: https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.14.0
[1.13.0]: https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.13.0
[1.12.0]: https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.12.0
[1.11.0]: https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.11.0
[1.10.1]: https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.10.1
[1.10.0]: https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.10.0
[1.9.0]: https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.9.0
[1.8.0]: https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.8.0
[1.7.2]: https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.7.2
[1.7.1]: https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.7.1
[1.7.0]: https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.7.0
[1.6.4]: https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.6.4
[1.6.3]: https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.6.3
[1.6.2]: https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.6.2
[1.6.1]: https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.6.1
[1.6.0]: https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.6.0
[1.5.0]: https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.5.0
[1.4.0]: https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.4.0
[1.3.3]: https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.3.3
[1.3.2]: https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.3.2
[1.3.1]: https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.3.1
[1.3.0]: https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.3.0
[1.2.1]: https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.2.1
[1.2.0]: https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.2.0
[1.1.1]: https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.1.1
[1.1.0]: https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.1.0
[1.0.0]: https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.0.0
