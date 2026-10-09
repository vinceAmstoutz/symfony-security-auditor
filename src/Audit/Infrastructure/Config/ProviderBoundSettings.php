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
 * The settings of a standalone configuration that name a model of the
 * provider it selects. Another provider does not serve them, so the first
 * call of the next audit would fail on every one of them.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ProviderBoundSettings
{
    private const array PATHS = ['attacker_model', 'reviewer_model', 'audit.escalation.cheap_model'];

    /**
     * @param array<array-key, mixed> $settings
     *
     * @return array{array<array-key, mixed>, list<string>} the settings without them, and the dotted names removed
     */
    public function removedFrom(array $settings): array
    {
        $removedPaths = [];
        foreach (self::PATHS as $path) {
            [$settings, $removed] = $this->withoutPath($settings, $path);
            if ($removed) {
                $removedPaths[] = $path;
            }
        }

        return [$settings, $removedPaths];
    }

    /**
     * A setting left empty names no model, so there is nothing to remove.
     *
     * @param array<array-key, mixed> $settings
     *
     * @return array{array<array-key, mixed>, bool}
     */
    private function withoutPath(array $settings, string $path): array
    {
        $keys = explode('.', $path, 2);
        $value = $settings[$keys[0]] ?? null;

        if (null === $value) {
            return [$settings, false];
        }

        if (!\array_key_exists(1, $keys)) {
            unset($settings[$keys[0]]);

            return [$settings, true];
        }

        if (!\is_array($value)) {
            return [$settings, false];
        }

        [$settings[$keys[0]], $removed] = $this->withoutPath($value, $keys[1]);

        return [$settings, $removed];
    }
}
