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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\WorkloadIdentity;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\RefusedTokenExchangeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\TransientHttpStatusException;

/** @internal not part of the BC promise, see docs/versioning.md */
interface AccessTokenProviderInterface
{
    /**
     * Returns an Anthropic access token that is still valid.
     *
     * @throws RefusedTokenExchangeException when the exchange is refused, or answers without an access token
     * @throws TransientHttpStatusException  when the token endpoint answers with a status worth retrying
     */
    public function accessToken(): string;
}
