<?php

/*
 * This file is part of the vinceamstoutz/symfony-security-auditor package.
 *
 * (c) Vincent Amstoutz <vincent.amstoutz.dev@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types=1);

$writtenByInit = [
    'standalone/init-anthropic-defaults',
    'standalone/init-force',
    'standalone/init-force-same-provider',
    'standalone/init-generic',
    'standalone/init-generic-no-api-key',
    'standalone/init-ollama',
    'standalone/init-openai',
    'standalone/init-then-audit',
];

$staticFindingReason = 'The configuration init writes turns audit.report_static_findings on, so the template |raw match becomes a reviewed finding';

return [
    [
        'scenarios' => ['api/domain-models', 'api/run-audit-use-case', 'api/run-audit-use-case-accepted-fingerprints', 'api/run-audit-use-case-bypass-cache', 'api/run-audit-use-case-scan-paths', 'api/run-audit-use-case-since'],
        'path' => 'runs.*.stdout.json.**.interrupted_calls',
        'match' => '/^<absent> -> 0$/',
        'reason' => 'The cost of a report counts the calls cut before their answer ended, which make it a minimum: a new field, 0 when no call was cut.',
        'changelog' => '#685',
    ],
    [
        'scenarios' => ['api/domain-models', 'api/run-audit-use-case', 'api/run-audit-use-case-accepted-fingerprints', 'api/run-audit-use-case-bypass-cache', 'api/run-audit-use-case-scan-paths', 'api/run-audit-use-case-since'],
        'path' => 'runs.*.stdout.json.**.interruptedCalls()',
        'match' => '/^<absent> -> 0$/',
        'reason' => 'AuditCost::interruptedCalls(), a new accessor for the same count.',
        'changelog' => '#685',
    ],
    [
        'scenarios' => ['cache/written-by-release', 'cache/written-by-release-batch', 'standalone/cache-written-by-release'],
        'path' => 'runs.*.stdout.json.coverage.*.status',
        'match' => '/^"cached" -> "analyzed"$/',
        'reason' => 'The attacker prompt version went from 19 to 22, so a run no longer serves the attacker answers 1.22.1 cached and analyzes those chunks again.',
        'changelog' => '#693',
    ],
    [
        'scenarios' => ['cache/written-by-release', 'cache/written-by-release-batch', 'standalone/cache-written-by-release'],
        'path' => 'runs.*.stdout.json.cost.*',
        'match' => '/^(?:0|0\\.0|\\[\\]) -> /',
        'reason' => 'The attacker prompt version went from 19 to 22, so a run no longer serves the attacker answers 1.22.1 cached and analyzes those chunks again.',
        'changelog' => '#693',
    ],
    [
        'scenarios' => ['cache/written-by-release', 'cache/written-by-release-batch', 'standalone/cache-written-by-release'],
        'path' => 'llm.lines',
        'match' => '/^\\+(?:attacker|attacker-json|tool-results) model=/',
        'reason' => 'The attacker prompt version went from 19 to 22, so a run no longer serves the attacker answers 1.22.1 cached and analyzes those chunks again.',
        'internal' => true,
    ],
    [
        'scenarios' => ['option/dry-run', 'option/show-scanned-dry-run', 'standalone/dry-run'],
        'path' => 'runs.*.stdout.lines',
        'match' => '/^[-+] \\* (?:Tokens: |Cost  : |  attacker \\(gpt-4o\\): )/',
        'reason' => 'The attacker skill blocks carry the Symfony 8.2, advisory, layered-architecture and taint-kind hunts, so a dry run estimates more attacker input tokens, and with them more output tokens and cost.',
        'changelog' => '#693',
    ],
    [
        'scenarios' => ['option/dry-run-json', 'standalone/dry-run-json'],
        'path' => 'runs.*.stdout.json.cost.**',
        'match' => '/^\\d+(?:\\.\\d+)? -> \\d+(?:\\.\\d+)?$/',
        'reason' => 'The attacker skill blocks carry the Symfony 8.2, advisory, layered-architecture and taint-kind hunts, so a dry run estimates more attacker input tokens, and with them more output tokens and cost.',
        'changelog' => '#693',
    ],
    [
        'scenarios' => $writtenByInit,
        'path' => 'files.home/config/symfony-security-auditor/config.yaml.lines',
        'match' => '/^\+(audit:|    report_static_findings: true)$/',
        'reason' => 'The configuration init writes turns audit.report_static_findings on for new users',
        'changelog' => '#696',
    ],
    [
        'scenarios' => ['standalone/init-then-audit'],
        'path' => 'runs.1.stdout.json.risk_score',
        'match' => '/^19 -> 24$/',
        'reason' => $staticFindingReason,
        'changelog' => '#696',
    ],
    [
        'scenarios' => ['standalone/init-then-audit'],
        'path' => 'runs.1.stdout.json.score',
        'match' => '/^81 -> 76$/',
        'reason' => $staticFindingReason,
        'changelog' => '#696',
    ],
    [
        'scenarios' => ['standalone/init-then-audit'],
        'path' => 'runs.1.stdout.json.total_vulnerabilities',
        'match' => '/^3 -> 4$/',
        'reason' => $staticFindingReason,
        'changelog' => '#696',
    ],
    [
        'scenarios' => ['standalone/init-then-audit'],
        'path' => 'runs.1.stdout.json.by_severity.medium',
        'match' => '/^0 -> 1$/',
        'reason' => $staticFindingReason,
        'changelog' => '#696',
    ],
    [
        'scenarios' => ['standalone/init-then-audit'],
        'path' => 'runs.1.stdout.json.vulnerabilities.2',
        'match' => '/^<absent> -> \{.*"title":"Static analysis: raw filter"/',
        'reason' => $staticFindingReason,
        'changelog' => '#696',
    ],
    [
        'scenarios' => ['standalone/init-then-audit'],
        'path' => 'runs.1.stdout.json.cost.**',
        'match' => '/^[0-9.]+ -> [0-9.]+$/',
        'reason' => 'Reviewing the static finding costs one more reviewer call',
        'changelog' => '#696',
    ],
    [
        'scenarios' => ['standalone/init-then-audit'],
        'path' => 'runs.1.stdout.json.coverage.11',
        'match' => '#^<absent> -> \{"stage":"reviewer","file":"templates/base\.html\.twig","status":"validated"\}$#',
        'reason' => $staticFindingReason,
        'changelog' => '#696',
    ],
    [
        'scenarios' => ['standalone/init-then-audit'],
        'path' => 'llm.lines',
        'match' => '/^\+(reviewer model=gpt-4o tools=record_review findings=1|tool-results model=gpt-4o count=1)$/',
        'reason' => 'The reviewer is asked about the static finding',
        'internal' => true,
    ],
    [
        'scenarios' => ['standalone/user-config-unknown-key'],
        'path' => 'runs.0.stderr.lines',
        'match' => '/^[+-] {2,3}[a-z_", .]+$/',
        'reason' => 'The list of valid audit keys quoted for an unknown key now names report_static_findings, which rewraps it',
        'changelog' => '#696',
    ],
    [
        'scenarios' => ['standalone/list'],
        'path' => 'runs.0.stdout.lines',
        'match' => '/^\\+\\s+auth:test\\s/',
        'reason' => 'The standalone binary lists the new auth:test command.',
        'changelog' => '#702',
    ],
    [
        'scenarios' => ['standalone/list'],
        'path' => 'runs.0.stdout.lines',
        'match' => '/^-\\s+completion\\s+Dump the shell completion script$/',
        'reason' => 'The standalone binary keeps the completion command of Symfony Console out of its listing; the command still runs.',
        'changelog' => '#713',
    ],
    [
        'scenarios' => ['standalone/auth-status-environment', 'standalone/auth-status-stored'],
        'path' => 'runs.0.stdout.lines',
        'match' => '/^\\+(?: Run "auth:test" to check that this key works\\. .*)?$/',
        'reason' => 'auth:status suggests auth:test, and what its request costs, once a key resolves.',
        'changelog' => '#702',
    ],
    [
        'scenarios' => ['standalone/init-anthropic-defaults', 'standalone/init-existing-confirmed', 'standalone/init-force', 'standalone/init-force-same-provider', 'standalone/init-generic', 'standalone/init-generic-no-api-key', 'standalone/init-ollama', 'standalone/init-openai', 'standalone/init-then-audit'],
        'path' => 'runs.0.stdout.lines',
        'match' => '/^[-+] (?:Installing support for .+|Downloading the [a-z]+ provider bridge with composer) — this can take a minute…$/',
        'reason' => 'init names the provider it installs support for as people know it, instead of its bridge package.',
        'changelog' => '#702',
    ],
    [
        'scenarios' => ['standalone/init-existing-confirmed'],
        'path' => 'runs.0.stdout.lines',
        'match' => '/.*/',
        'reason' => 'init no longer asks which environment variable holds the API key, so the scripted "yes" now answers the overwrite question and the configuration is rewritten instead of the run aborting.',
        'changelog' => '#702',
    ],
    [
        'scenarios' => ['standalone/init-existing-confirmed'],
        'path' => 'files.home/config/symfony-security-auditor/config.yaml.lines',
        'match' => '/.*/',
        'reason' => 'init no longer asks which environment variable holds the API key, so the scripted "yes" now answers the overwrite question and the configuration is rewritten instead of the run aborting.',
        'changelog' => '#702',
    ],
    [
        'scenarios' => ['standalone/init-existing-confirmed'],
        'path' => 'files.home/data/symfony-security-auditor/composer.json',
        'match' => '/^null -> /',
        'reason' => 'init no longer asks which environment variable holds the API key, so the scripted "yes" now answers the overwrite question and the configuration is rewritten instead of the run aborting.',
        'changelog' => '#702',
    ],
    [
        'scenarios' => ['standalone/help-init'],
        'path' => 'runs.0.stdout.lines',
        'match' => '/.*/',
        'reason' => 'init takes the new --deployment option for Azure OpenAI, which realigns every option row of its help.',
        'changelog' => '#702',
    ],
    [
        'scenarios' => ['standalone/init-base-url-refused'],
        'path' => 'runs.0.stdout.lines',
        'match' => '/^[-+] (?:\\[ERROR\\] --base-url applies to the platforms that expose one|\\s+(?:generic|openresponses)\\.<instance>)/',
        'reason' => 'init writes Azure OpenAI now, so the --base-url refusal names azure.<instance> among the platforms that take one.',
        'changelog' => '#702',
    ],
    [
        'scenarios' => ['standalone/init-generic-no-api-key', 'standalone/init-ollama'],
        'path' => 'runs.0.stdout.lines',
        'match' => '/^[-+] (?:-+ -+|\\s+(?:Provider|Model|API key variable)\\s.*)$/',
        'reason' => 'init leaves the API key row out of its summary when the configuration carries no credential.',
        'changelog' => '#702',
    ],
    [
        'scenarios' => ['baseline/generated-by-release-console', 'format/console', 'format/console-no-finding', 'format/console-to-file', 'format/executive-to-file', 'format/github-comment-to-file', 'format/github-to-file', 'format/html-to-file', 'format/json-to-file', 'format/junit-to-file', 'format/markdown-to-file', 'format/sarif-to-file', 'option/generate-baseline-console', 'option/project-path-omitted', 'option/project-path-only', 'output/config-key', 'output/dev-null', 'output/existing-file', 'output/missing-directory', 'output/relative-path', 'output/short-option', 'run/empty-project-console', 'run/scan-layout-formats', 'standalone/format-console', 'standalone/output-dev-null', 'standalone/output-file'],
        'path' => 'runs.*.stdout.lines',
        'match' => '/^(?:- The audit makes many LLM calls \\xE2\\x80\\x94 typically several minutes, 20\\+ minutes on large projects\\.$|\\+ The audit makes many LLM calls: typically several minutes, 20\\+ minutes on large projects\\.$)/',
        'reason' => 'The long-run notice is written with a colon in place of a dash.',
        'changelog' => '#711',
    ],
    [
        'scenarios' => ['format/html', 'format/html-no-finding', 'report-commands/trend-html', 'standalone/format-html'],
        'path' => 'runs.0.stdout.lines',
        'match' => '/^[-+] /',
        'reason' => 'The html report and trend page open with the console banner and use its pink and navy colours, which rewrites their markup and stylesheet.',
        'changelog' => '#720',
    ],
    [
        'scenarios' => ['format/html-to-file'],
        'path' => 'files.out/report.html.lines',
        'match' => '/^[-+] /',
        'reason' => 'The html report and trend page open with the console banner and use its pink and navy colours, which rewrites their markup and stylesheet.',
        'changelog' => '#720',
    ],
    [
        'scenarios' => ['run/scan-layout-formats'],
        'path' => 'runs.3.stdout.lines',
        'match' => '/^[-+] /',
        'reason' => 'The html report and trend page open with the console banner and use its pink and navy colours, which rewrites their markup and stylesheet.',
        'changelog' => '#720',
    ],
    [
        'scenarios' => ['standalone/auth-status-environment', 'standalone/auth-status-stored', 'standalone/auth-status-other-variable', 'standalone/auth-status-invalid-name'],
        'path' => 'runs.0.stdout.lines',
        'match' => '/^\\+(?: -{10} -+| {2}(?:Provider|Model|Billing) {3,}.+)?$/',
        'reason' => 'auth:status first names the provider, the models and what each call bills.',
        'changelog' => '#724',
    ],
    [
        'scenarios' => ['standalone/auth-remove'],
        'path' => 'runs.1.stdout.lines',
        'match' => '/^\\+(?: -{10} -+| {2}(?:Provider|Model|Billing) {3,}.+)?$/',
        'reason' => 'auth:status first names the provider, the models and what each call bills.',
        'changelog' => '#724',
    ],
    [
        'scenarios' => ['baseline/generated-by-release-console', 'format/console', 'format/console-no-finding', 'format/console-to-file', 'format/executive-to-file', 'format/github-comment-to-file', 'format/github-to-file', 'format/html-to-file', 'format/json-to-file', 'format/junit-to-file', 'format/markdown-to-file', 'format/sarif-to-file', 'option/dry-run', 'option/generate-baseline-console', 'option/project-path-omitted', 'option/project-path-only', 'option/show-scanned', 'option/show-scanned-dry-run', 'output/config-key', 'output/dev-null', 'output/directory', 'output/existing-file', 'output/missing-directory', 'output/relative-path', 'output/short-option', 'run/empty-project-console', 'run/scan-layout-formats', 'standalone/dry-run', 'standalone/format-console', 'standalone/output-dev-null', 'standalone/output-file', 'standalone/show-scanned', 'standalone/stack-working-directory-scan-paths'],
        'path' => 'runs.*.stdout.lines',
        'match' => '/^- Pipeline: Ingestion -> Mapping -> Audit \\(Attacker vs Reviewer\\)$/',
        'reason' => 'The audit header prints the fixed pipeline line only with -v.',
        'changelog' => '#760',
    ],
    [
        'scenarios' => ['baseline/generated-by-release', 'baseline/generated-by-release-config-key', 'baseline/generated-by-release-on-changed-project', 'baseline/generated-by-release-regenerated', 'baseline/generated-by-release-sarif', 'cache/written-by-release', 'cache/written-by-release-batch', 'cache/written-by-release-changed-project', 'cache/written-by-release-no-cache', 'config-file/architecture-01', 'config-file/architecture-02', 'config-file/ci-01', 'config-file/ci-02', 'config-file/configuration-02', 'config-file/configuration-03', 'config-file/configuration-04', 'config-file/configuration-05', 'config-file/configuration-06', 'config-file/configuration-07', 'config-file/cost-and-performance-01', 'config-file/example-ci-optimized', 'config-file/example-cost-aware', 'config-file/example-dev-fast', 'config-file/faq-01', 'config-file/faq-03', 'config-file/faq-04', 'config-file/faq-05', 'config-file/readme-01', 'config-file/readme-02', 'config-file/troubleshooting-01', 'config-file/troubleshooting-02', 'config-file/troubleshooting-03', 'config-file/troubleshooting-04', 'format/config-key', 'format/executive', 'format/executive-no-finding', 'format/github', 'format/github-comment', 'format/github-comment-no-finding', 'format/github-incomplete-run', 'format/github-no-finding', 'format/html', 'format/html-no-finding', 'format/json', 'format/json-no-finding', 'format/junit', 'format/junit-no-finding', 'format/markdown', 'format/markdown-no-finding', 'format/sarif', 'format/sarif-incomplete-run', 'format/sarif-no-finding', 'format/short-option', 'gate/config-fail-on-critical', 'gate/config-fail-on-incomplete', 'gate/config-fail-on-low', 'gate/config-min-score', 'gate/fail-on-and-min-score', 'gate/fail-on-critical', 'gate/fail-on-high', 'gate/fail-on-low', 'gate/fail-on-medium', 'gate/fail-on-safe', 'gate/incomplete-run', 'gate/incomplete-run-config-fail-on-incomplete', 'gate/incomplete-run-fail-on-incomplete', 'gate/min-score--5', 'gate/min-score-0', 'gate/min-score-100', 'gate/min-score-101', 'gate/min-score-150', 'gate/min-score-80', 'gate/min-score-81', 'gate/min-score-81.5', 'gate/min-score-82', 'gate/no-finding-min-score-100', 'option/alias', 'option/baseline-malformed-file', 'option/baseline-missing-file', 'option/dry-run-json', 'option/fail-on-incomplete', 'option/generate-baseline', 'option/no-cache', 'option/path-short', 'option/project-path-missing', 'option/project-path-relative', 'option/since-without-git', 'run/advisory-lookup', 'run/base', 'run/budget-tokens-exceeded', 'run/budget-unpriced-model', 'run/budget-within', 'run/cache-cold', 'run/cache-cold-batch', 'run/chunking-type', 'run/concurrent', 'run/concurrent-json', 'run/custom-client-and-stage', 'run/custom-client-and-stage-json', 'run/dedupe-overlapping', 'run/dedupe-same-id', 'run/empty-project', 'run/escalation', 'run/escalation-default', 'run/excluded-types', 'run/finding-absolute-path', 'run/finding-path-spellings', 'run/included-types', 'run/iterations', 'run/iterations-overlap', 'run/iterations-reviewer-sequence', 'run/json-collection', 'run/min-confidence', 'run/path-directory', 'run/path-dot', 'run/path-dot-dot', 'run/path-dot-slash', 'run/path-empty', 'run/path-file', 'run/path-file-and-directory', 'run/path-glob', 'run/path-missing', 'run/path-mixed', 'run/path-outside-included-paths', 'run/path-overlapping', 'run/path-secret-files', 'run/path-spelled-with-dot-and-backslash', 'run/path-tilde', 'run/path-upper-case', 'run/path-whitespace', 'run/poc-and-fix', 'run/prescan-off', 'run/profile-balanced', 'run/profile-fast', 'run/profile-thorough', 'run/provider-error', 'run/provider-error-fail-on-incomplete', 'run/provider-retried', 'run/provider-unauthorized', 'run/rate-limited', 'run/reviewer-accepted-spellings', 'run/reviewer-accepted-spellings-batch', 'run/reviewer-accepted-spellings-fail-on-incomplete', 'run/reviewer-batch', 'run/reviewer-batch-json', 'run/reviewer-tools', 'run/scan-layout', 'run/scan-layout-formats', 'run/scan-layout-git', 'run/scan-layout-included-paths', 'run/scan-layout-no-gitignore', 'run/since', 'run/since-tools', 'run/sloppy-findings-fail-on-incomplete', 'run/sloppy-findings-json', 'run/sloppy-findings-structured', 'run/split-models', 'run/tools-disabled', 'standalone/cache-written-by-release', 'standalone/credential-store-used', 'standalone/doc-generic-gateway', 'standalone/dry-run-json', 'standalone/format-executive', 'standalone/format-github', 'standalone/format-github-comment', 'standalone/format-html', 'standalone/format-json', 'standalone/format-junit', 'standalone/format-markdown', 'standalone/format-sarif', 'standalone/generate-baseline-and-use', 'standalone/init-then-audit', 'standalone/path', 'standalone/project-config-budget-tightened', 'standalone/project-config-hyphenated-keys', 'standalone/run-alias-audit-run', 'standalone/run-inside-project', 'standalone/since', 'standalone/stack-flag-over-working-directory', 'standalone/stack-inside-project', 'standalone/stack-project-directory', 'standalone/stack-user-config-gate', 'standalone/stack-user-config-only', 'standalone/stack-working-directory', 'standalone/stack-working-directory-and-project', 'standalone/stack-working-directory-model', 'standalone/stack-working-directory-profile', 'standalone/user-config-full', 'standalone/user-config-http-timeout', 'standalone/user-config-hyphenated-keys', 'standalone/user-config-provider-selector'],
        'path' => 'runs.*.stderr.lines',
        'match' => '/^- Pipeline: Ingestion -> Mapping -> Audit \\(Attacker vs Reviewer\\)$/',
        'reason' => 'The audit header prints the fixed pipeline line only with -v.',
        'changelog' => '#760',
    ],
];
