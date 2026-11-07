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

return [
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
];
