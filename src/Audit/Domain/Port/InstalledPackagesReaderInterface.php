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

/**
 * The packages the audited project's lockfile installs.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
interface InstalledPackagesReaderInterface
{
    /**
     * @return array<string, string>|null package name => locked version, `null` when there is no lockfile it can read
     */
    public function read(string $projectPath): ?array;
}
