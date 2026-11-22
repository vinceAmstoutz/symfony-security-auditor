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

namespace VinceAmstoutz\SymfonySecurityAuditor\Command;

/**
 * Sends one short request to the configured provider, so `doctor
 * --check-connection` can tell whether the key, model and endpoint work.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
interface ConnectionCheckInterface
{
    /**
     * @return ?string why the request failed, null when the provider answered
     */
    public function failureReason(): ?string;
}
