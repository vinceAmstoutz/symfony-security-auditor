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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory;

/**
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class AdvisorySnapshot
{
    public function __construct(
        public string $key,
        public ComposerAuditAdvisoryDatabase $composerAuditAdvisoryDatabase,
        public int $expiresAt,
    ) {}

    public function serves(string $key, int $now): bool
    {
        return $this->key === $key && $now < $this->expiresAt;
    }
}
