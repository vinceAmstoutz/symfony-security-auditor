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
];
