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

/**
 * Static, test-friendly advisory database. Bundle's default is
 * `ComposerAuditAdvisoryDatabase`, which queries Packagist's live advisory feed via
 * `composer audit`; this implementation is the deterministic fallback used by tests
 * and by hosts that explicitly opt out of running composer at audit time.
 *
 * Returns every advisory registered for the package — version-constraint filtering
 * is delegated to the LLM, which already has the installed version and the
 * advisory's `affected_versions` text in front of it.
 */
final readonly class InMemoryAdvisoryDatabase implements AdvisoryDatabaseInterface
{
    /**
     * @param array<string, list<array{cve: ?string, title: string, summary: string, affected_versions: string, link: ?string}>> $entriesByPackage
     */
    public function __construct(private array $entriesByPackage = []) {}

    public function lookup(string $packageName, string $installedVersion): array
    {
        return $this->entriesByPackage[$packageName] ?? [];
    }
}
