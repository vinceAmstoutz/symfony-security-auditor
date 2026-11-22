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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port;

interface AdvisoryDatabaseInterface
{
    /**
     * The known security advisories that affect the package at that version,
     * from any source.
     *
     * @return list<array{cve: ?string, title: string, summary: string, affected_versions: string, link: ?string}>
     */
    public function lookup(string $packageName, string $installedVersion): array;
}
