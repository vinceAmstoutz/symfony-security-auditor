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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\WorkloadIdentity\WorkloadIdentityFederation;

/**
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class StandalonePlatformConfig
{
    private const array STAND_IN_CREDENTIALS = [StandalonePlatformConfigResolver::UNNEEDED_CREDENTIAL, WorkloadIdentityFederation::API_KEY_PLACEHOLDER];

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
        return ['platform' => CliAgentPlatforms::withoutCliAgents($this->platform)];
    }

    /**
     * Whether the run calls this platform: the one `provider:` selects, else
     * the only one the configuration declares.
     */
    public function runsOn(string $platform): bool
    {
        return null === $this->activeProvider
            ? [$platform] === array_keys($this->platform)
            : $platform === $this->activeProvider;
    }

    /**
     * Names the credential the run authenticates with without disclosing it;
     * null when the run needs none, or reads only a value standing in for one
     * such as the workload identity federation placeholder.
     */
    public function credentialIdentity(): ?CredentialIdentity
    {
        $apiKey = PlatformApiKey::valueForProvider($this->platform, $this->activeProvider);

        return null === $apiKey || \in_array($apiKey, self::STAND_IN_CREDENTIALS, true)
            ? null
            : CredentialIdentity::of(ContainerParameterSyntax::unescape($apiKey));
    }
}
