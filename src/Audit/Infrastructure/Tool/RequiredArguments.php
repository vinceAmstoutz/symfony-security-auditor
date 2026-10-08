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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Tool;

/**
 * Checks a tool call against the `required` list of the tool's own input
 * schema, for the providers that do not enforce that schema before invoking
 * the tool. A violation comes back as the `Error: …` text the model reads
 * inside the tool loop and retries from, so a call that cannot be used is
 * never acknowledged as recorded.
 *
 * Only a missing (absent or `null`) argument and a non-string value for a
 * string argument are refused: numbers and booleans a provider stringified
 * are normalised downstream (`VulnerabilityFactory`, `VerdictApplier`) and
 * must keep being accepted.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class RequiredArguments
{
    /**
     * @param array{required: list<string>, properties: array<string, array<string, mixed>>} $schema
     * @param array<string, mixed>                                                           $arguments
     */
    public static function violation(array $schema, array $arguments): ?string
    {
        foreach ($schema['required'] as $name) {
            $violation = self::violationOf($name, $arguments[$name] ?? null, $schema['properties'][$name]['type'] ?? null);
            if (null !== $violation) {
                return $violation;
            }
        }

        return null;
    }

    private static function violationOf(string $name, mixed $value, mixed $declaredType): ?string
    {
        if (null === $value) {
            return \sprintf('Error: missing required argument "%s".', $name);
        }

        if ('string' === $declaredType && !\is_string($value)) {
            return \sprintf('Error: argument "%s" must be a string.', $name);
        }

        return null;
    }
}
