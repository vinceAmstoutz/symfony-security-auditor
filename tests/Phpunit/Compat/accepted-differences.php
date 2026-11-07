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
        'scenarios' => ['standalone/user-config-unknown-key'],
        'path' => 'runs.*.stderr.lines',
        'match' => '/^[-+]  /',
        'reason' => 'The error naming an unknown `audit` key lists the new `coverage_critic` option among the available ones.',
        'changelog' => '#695',
    ],
];
