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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory;

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AdvisoryDatabaseInterface;

/**
 * Advisory database of fixed entries, for tests and hosts that do not run
 * composer. Returns every advisory of the package whatever the installed
 * version: the LLM compares it with `affected_versions`.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class InMemoryAdvisoryDatabase implements AdvisoryDatabaseInterface
{
    /**
     * @var array<string, list<array{cve: ?string, title: string, summary: string, affected_versions: string, link: ?string}>>
     */
    private array $entriesByPackage;

    /**
     * @param array<string, list<array{cve: ?string, title: string, summary: string, affected_versions: string, link: ?string}>> $entriesByPackage
     */
    public function __construct(array $entriesByPackage = [])
    {
        $normalized = [];
        foreach ($entriesByPackage as $packageName => $entries) {
            $normalized[PackageNameNormalizer::normalize($packageName)] = $entries;
        }

        $this->entriesByPackage = $normalized;
    }

    #[Override]
    public function lookup(string $packageName, string $installedVersion): array
    {
        return $this->entriesByPackage[PackageNameNormalizer::normalize($packageName)] ?? [];
    }
}
