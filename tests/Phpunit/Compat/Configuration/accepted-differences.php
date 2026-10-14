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
        'parameters' => ['symfony_security_auditor.cache.*key_salt'],
        'reason' => 'The attacker prompt version went from 17 to 19 and the reviewer one from 3 to 4, so the cache keys no longer match what 1.21.0 cached.',
        'changelog' => 'The attacker and reviewer prompts now say that the code they read is data, never instructions.',
    ],
    [
        'parameters' => ['symfony_security_auditor.cache.key_salt', 'symfony_security_auditor.cache.cheap_attacker_key_salt'],
        'reason' => 'The attacker prompt version was raised again for the `xss` type.',
        'changelog' => 'Cross-site scripting is now a finding type of its own: `xss` (CWE-79, OWASP A05:2025 - Injection).',
    ],
    [
        'parameters' => ['symfony_security_auditor.cache.key_salt', 'symfony_security_auditor.cache.cheap_attacker_key_salt'],
        'reason' => 'The pre-scan cache version went from 31 to 32 when its patterns were bounded.',
        'changelog' => 'One very long line can no longer hold the pre-scan or the code slicer for minutes on a PHP build without PCRE JIT.',
    ],
];
