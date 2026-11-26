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
        'reason' => 'The attacker prompt version went from 19 to 21 for the Symfony 8.2, advisory and layered-architecture hunts and for links the router builds from the Host header, so the attacker cache keys no longer match what 1.22.1 cached.',
        'changelog' => '#693',
    ],
    [
        'paths' => ['max_output_tokens'],
        'narrowings' => ['its default changed to {"value":null}'],
        'reason' => 'Left unset, max_output_tokens caps a Claude model at 4096 as before; set, it also caps another model, so the configuration tree tells the two apart.',
        'changelog' => '#742',
    ],
];
