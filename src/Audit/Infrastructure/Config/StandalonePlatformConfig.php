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

    /**
     * Names the credential the run will authenticate with, so output can say
     * which key was spent without ever printing it. A run told it needs no
     * credential carries the sentinel instead of a key, and has no identity
     * worth showing.
     */
    public function credentialIdentity(): ?CredentialIdentity
    {
        $apiKey = PlatformApiKey::valueIn($this->platform);

        return null === $apiKey || StandalonePlatformConfigResolver::UNNEEDED_CREDENTIAL === $apiKey
            ? null
            : CredentialIdentity::of($apiKey);
    }
}
