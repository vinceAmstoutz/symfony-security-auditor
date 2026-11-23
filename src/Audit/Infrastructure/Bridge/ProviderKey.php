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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge;

/**
 * Splits a configured `provider` into its `symfony/ai` platform and optional
 * instance: `generic.my_gateway` names the `my_gateway` instance of the
 * `generic` platform.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class ProviderKey
{
    public const string INSTANCE_SEPARATOR = '.';

    private function __construct(
        public string $platform,
        public ?string $instance,
    ) {}

    public static function of(string $provider): self
    {
        $parts = explode(self::INSTANCE_SEPARATOR, $provider, 2);
        $instance = trim($parts[1] ?? '');

        return new self(trim($parts[0]), '' !== $instance ? $instance : null);
    }
}
