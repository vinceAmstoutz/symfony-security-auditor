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
 * Extracts the route and access-control metadata of a controller file.
 * Implementations MUST return an empty list for a file they cannot parse,
 * never throw.
 */
interface ControllerAccessControlParserInterface
{
    /**
     * @return list<RouteAccessControl> one entry per public action method discovered in the file
     */
    public function parse(ProjectFile $projectFile): array;
}
