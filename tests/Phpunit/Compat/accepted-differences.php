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
        'reason' => 'The attacker prompt version went from 19 to 20, so a run no longer serves the attacker answers 1.22.1 cached and analyzes those chunks again.',
        'changelog' => '#693',
    ],
    [
        'scenarios' => ['cache/written-by-release', 'cache/written-by-release-batch', 'standalone/cache-written-by-release'],
        'path' => 'runs.*.stdout.json.cost.*',
        'match' => '/^(?:0|0\\.0|\\[\\]) -> /',
        'reason' => 'The attacker prompt version went from 19 to 20, so a run no longer serves the attacker answers 1.22.1 cached and analyzes those chunks again.',
        'changelog' => '#693',
    ],
    [
        'scenarios' => ['cache/written-by-release', 'cache/written-by-release-batch', 'standalone/cache-written-by-release'],
        'path' => 'llm.lines',
        'match' => '/^\\+(?:attacker|attacker-json|tool-results) model=/',
        'reason' => 'The attacker prompt version went from 19 to 20, so a run no longer serves the attacker answers 1.22.1 cached and analyzes those chunks again.',
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
        'scenarios' => ['standalone/list'],
        'path' => 'runs.0.stdout.lines',
        'match' => '/^\+\s+audit:fix\s/',
        'reason' => 'The standalone binary lists the new audit:fix command.',
        'changelog' => '#690',
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
        'path' => 'runs.1.stdout.json.coverage.7',
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
        'scenarios' => ['standalone/auth-status-environment', 'standalone/auth-status-stored'],
        'path' => 'runs.0.stdout.lines',
        'match' => '/^\\+(?: Run "auth:test" to check that the provider accepts this key\\. .*)?$/',
        'reason' => 'auth:status suggests auth:test, and what its request costs, once a key resolves.',
        'changelog' => '#702',
    ],
];
