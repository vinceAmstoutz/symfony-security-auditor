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

use UnexpectedValueException;

/**
 * One entry of `accepted-differences.php` that accepts a change to the
 * contract of recorded configuration paths: the paths, the exact narrowings
 * the comparison reports for them (such as `its default changed to
 * {"value":"claude-opus-5-5"}`), why, and the pull request (`#123`) that a
 * `CHANGELOG.md` bullet under `## [Unreleased]` links to announce it.
 */
final readonly class AcceptedContractChange
{
    /**
     * @param list<string> $paths
     * @param list<string> $narrowings
     */
    private function __construct(
        public array $paths,
        public array $narrowings,
        public string $reason,
        public string $changelog,
    ) {}

    /**
     * @param array<mixed> $entry
     */
    public static function fromArray(array $entry): self
    {
        $paths = self::strings($entry['paths'] ?? null);
        $narrowings = self::strings($entry['narrowings'] ?? null);
        $reason = $entry['reason'] ?? null;
        $changelog = $entry['changelog'] ?? null;

        if ([] === $paths || [] === $narrowings || !\is_string($reason) || !\is_string($changelog) || '' === trim($reason) || 4 !== \count($entry)) {
            throw new UnexpectedValueException('An accepted contract change has exactly a list of "paths", a list of "narrowings", a "reason" and a "changelog".');
        }

        return new self($paths, $narrowings, $reason, $changelog);
    }

    public function covers(string $path, string $narrowing): bool
    {
        return \in_array($path, $this->paths, true) && \in_array($narrowing, $this->narrowings, true);
    }

    /**
     * @return list<string>
     */
    private static function strings(mixed $value): array
    {
        return \is_array($value) && array_is_list($value) && array_filter($value, \is_string(...)) === $value ? $value : [];
    }
}
