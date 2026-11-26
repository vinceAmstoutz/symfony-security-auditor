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
 * Which roles the configuration gives an output cap: a model other than
 * Claude is capped only then, since its cap also counts the reasoning tokens
 * and a default one could cut a thinking model's answer short.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class ConfiguredOutputCaps
{
    private function __construct(
        public bool $attacker,
        public bool $reviewer,
    ) {}

    /**
     * @param array<array-key, mixed> $config the processed bundle configuration
     */
    public static function in(array $config): self
    {
        $shared = null !== ($config['max_output_tokens'] ?? null);

        return new self(
            $shared || null !== ($config['attacker_max_output_tokens'] ?? null),
            $shared || null !== ($config['reviewer_max_output_tokens'] ?? null),
        );
    }
}
