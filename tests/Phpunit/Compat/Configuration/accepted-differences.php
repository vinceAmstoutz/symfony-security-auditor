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
        'parameters' => ['symfony_security_auditor.cache.key_salt', 'symfony_security_auditor.cache.cheap_attacker_key_salt'],
        'reason' => 'The attacker prompt version went from 19 to 20 for the Symfony 8.2, advisory and layered-architecture hunts, so the attacker cache keys no longer match what 1.22.1 cached.',
        'changelog' => '#693',
    ],
];
