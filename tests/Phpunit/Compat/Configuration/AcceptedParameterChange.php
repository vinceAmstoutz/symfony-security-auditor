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
 * One entry of `accepted-differences.php`: the published container parameters
 * whose value may differ from the recorded release (`*` stands for any run of
 * characters), why, and the bold summary of the `CHANGELOG.md` bullet under
 * `## [Unreleased]` that announces it.
 */
final readonly class AcceptedParameterChange
{
    /**
     * @param list<string> $parameters
     */
    private function __construct(
        public array $parameters,
        public string $reason,
        public string $changelog,
    ) {}

    /**
     * @param array<mixed> $entry
     */
    public static function fromArray(array $entry): self
    {
        $parameters = $entry['parameters'] ?? null;
        $reason = $entry['reason'] ?? null;
        $changelog = $entry['changelog'] ?? null;

        if (!\is_array($parameters) || [] === $parameters || !array_is_list($parameters) || array_filter($parameters, \is_string(...)) !== $parameters || !\is_string($reason) || !\is_string($changelog) || '' === trim($reason) || 3 !== \count($entry)) {
            throw new UnexpectedValueException('An accepted parameter change has exactly a list of "parameters", a "reason" and a "changelog".');
        }

        return new self($parameters, $reason, $changelog);
    }

    public function covers(string $parameter): bool
    {
        return [] !== array_filter($this->parameters, static fn (string $pattern): bool => fnmatch($pattern, $parameter, \FNM_NOESCAPE));
    }
}
