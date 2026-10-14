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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Configuration;

/**
 * Where an added configuration path must be documented: `docs/versioning.md`
 * lists the key that was added (the path itself, or the first of its
 * ancestors the recorded release did not have), and `resources/schema.json`
 * describes the path, as `ConfigurationSchemaEnumParityTest` checks its
 * choices.
 */
final readonly class DocumentedPaths
{
    /**
     * @param array<string, mixed> $recordedPaths
     */
    public static function isListed(string $path, array $recordedPaths, string $versioning): bool
    {
        $segments = explode('.', $path);
        $added = $path;
        $counter = \count($segments);

        for ($length = 1; $length <= $counter; ++$length) {
            $candidate = implode('.', \array_slice($segments, 0, $length));
            if (!\array_key_exists($candidate, $recordedPaths)) {
                $added = $candidate;

                break;
            }
        }

        return str_contains($versioning, \sprintf('`%s`', str_replace('.'.ConfigurationTree::ENTRY, '', $added)));
    }

    public static function isInSchema(string $path, mixed $schema, string $root): bool
    {
        $node = self::keyword(self::keyword($schema, 'properties'), $root);
        foreach (explode('.', $path) as $segment) {
            $node = ConfigurationTree::ENTRY === $segment
                ? self::keyword($node, 'items') ?? self::keyword($node, 'additionalProperties')
                : self::keyword(self::keyword($node, 'properties'), $segment);
        }

        return \is_array($node);
    }

    private static function keyword(mixed $schema, string $keyword): mixed
    {
        return \is_array($schema) ? $schema[$keyword] ?? null : null;
    }
}
