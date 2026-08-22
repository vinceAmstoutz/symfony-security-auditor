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
final readonly class StandaloneConfig
{
    /**
     * @param array<array-key, mixed> $auditConfig
     */
    public function __construct(
        public array $auditConfig,
        public StandalonePlatformConfig $platform,
    ) {}

    public function offlineOnly(): bool
    {
        return self::offlineOnlyIn($this->auditConfig);
    }

    /**
     * Reads `privacy.offline_only` straight off a raw parsed config, for
     * callers that must answer the question before a full `StandaloneConfig`
     * can be built — `self-update` runs before "init" has ever written a
     * platform.
     *
     * @param array<array-key, mixed> $auditConfig
     */
    public static function offlineOnlyIn(array $auditConfig): bool
    {
        $privacy = $auditConfig['privacy'] ?? null;

        return \is_array($privacy) && true === ($privacy['offline_only'] ?? false);
    }
}
