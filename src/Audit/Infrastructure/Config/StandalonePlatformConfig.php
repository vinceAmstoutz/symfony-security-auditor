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
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class StandalonePlatformConfig
{
    /**
     * @param array<array-key, mixed> $platform the symfony/ai `ai.platform` config, env-resolved, passed through untouched
     */
    public function __construct(
        public array $platform,
        public ?string $activeProvider = null,
    ) {}

    /**
     * @return array{platform: array<array-key, mixed>}
     */
    public function toAiConfig(): array
    {
        return ['platform' => $this->platform];
    }
}
