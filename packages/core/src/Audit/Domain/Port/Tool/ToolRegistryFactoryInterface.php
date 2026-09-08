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

namespace VinceAmstoutz\SecurityAuditor\Audit\Domain\Port\Tool;

use VinceAmstoutz\SecurityAuditor\Audit\Domain\Model\ProjectFile;

interface ToolRegistryFactoryInterface
{
    /**
     * @param list<ProjectFile> $projectFiles
     */
    public function forProjectFiles(array $projectFiles): ToolRegistry;
}
