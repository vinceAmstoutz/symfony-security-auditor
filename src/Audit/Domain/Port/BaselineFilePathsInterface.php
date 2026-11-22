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
 * The paths the run's baseline names a project file by (`./src/A.php`,
 * `src\A.php`, `/src/A.php` or an absolute path), so an entry keeps accepting
 * a finding the model names by another spelling.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
interface BaselineFilePathsInterface
{
    /**
     * The baseline's paths that name the project file `$filePath`, in the
     * baseline's order.
     *
     * @return list<string>
     */
    public function naming(string $filePath): array;
}
