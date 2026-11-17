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

$arguments = is_array($_SERVER['argv'] ?? null) ? $_SERVER['argv'] : [];

echo 'ran: '.implode(' ', array_filter(array_slice($arguments, 1), is_string(...))).\PHP_EOL;
