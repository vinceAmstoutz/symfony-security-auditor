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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RouteAccessControl;

/**
 * Extracts route/access-control metadata from a single controller file. Implementations
 * must degrade silently (return an empty list) when the file cannot be parsed — a
 * single broken controller must not abort the mapping stage.
 */
interface ControllerAccessControlParserInterface
{
    /**
     * @return list<RouteAccessControl> one entry per public action method discovered in the file
     */
    public function parse(ProjectFile $projectFile): array;
}
