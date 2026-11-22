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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config;

/**
 * Where `init` writes the selected platform reaches it: the settings, each
 * optional, a platform's connection block takes beside its API key.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class PlatformConnection
{
    public function __construct(
        public ?string $baseUrl = null,
        public ?string $endpoint = null,
        public ?string $deployment = null,
        public ?string $effort = null,
    ) {}

    public function withEffort(?string $effort): self
    {
        return new self($this->baseUrl, $this->endpoint, $this->deployment, $effort);
    }
}
