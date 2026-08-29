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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port;

/**
 * One prompt pair bound for a batch-capable client.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class LLMRequest
{
    public function __construct(
        public string $system,
        public string $user,
    ) {}
}
