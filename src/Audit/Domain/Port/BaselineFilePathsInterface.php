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
 * The paths the run's baseline names a project file by: a baseline written
 * before 1.22 holds a finding under the path the model echoed then
 * (`./src/A.php`, `src\A.php`, `/src/A.php` or an absolute path), and keeps
 * accepting it once the model names the file otherwise.
 *
 * @internal not part of the BC promise — see docs/versioning.md
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
