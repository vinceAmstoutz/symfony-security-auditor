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
 * Splits a configured `provider` into the `symfony/ai` platform it names and
 * the optional instance within it. Platforms declared with
 * `useAttributeAsKey` (`generic`, `azure`, `bedrock`, `openresponses`, …)
 * register one service per instance as `ai.platform.<platform>.<instance>`,
 * so `provider: generic.my_gateway` selects the `my_gateway` instance of the
 * `generic` platform while its bridge package is still built from `generic`
 * alone.
 *
 * @internal not part of the BC promise — see docs/versioning.md
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
        $instance = $parts[1] ?? '';

        return new self($parts[0], '' !== $instance ? $instance : null);
    }
}
