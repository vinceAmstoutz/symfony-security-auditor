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
 * The provider, models and CLI settings the user configuration names, read
 * as written, without resolving any placeholder.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class ConfiguredProvider
{
    public function __construct(
        public string $name,
        public ?string $model = null,
        public ?string $reviewerModel = null,
        public ?string $effort = null,
        public ?string $cliBinary = null,
        public bool $takesApiKey = false,
        public ?string $apiKeyVariable = null,
    ) {}

    /**
     * @param array<array-key, mixed> $parsed   the user configuration
     * @param array<array-key, mixed> $settings the block `platform:` holds for this provider
     */
    public static function of(string $name, array $parsed, array $settings): self
    {
        $apiKey = PlatformApiKey::valueIn($settings);

        return new self(
            $name,
            self::text($parsed['model'] ?? null),
            self::text($parsed['reviewer_model'] ?? null),
            self::text($settings['effort'] ?? null),
            self::text($settings['cli_binary'] ?? null),
            null !== $apiKey,
            null !== $apiKey ? EnvPlaceholder::in($apiKey)?->variableName : null,
        );
    }

    private static function text(mixed $value): ?string
    {
        return \is_string($value) && '' !== $value ? $value : null;
    }
}
