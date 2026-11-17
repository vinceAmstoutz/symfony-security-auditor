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
];
