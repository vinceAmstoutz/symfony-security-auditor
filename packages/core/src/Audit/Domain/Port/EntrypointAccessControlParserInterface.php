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

namespace VinceAmstoutz\SecurityAuditor\Audit\Domain\Port;

use VinceAmstoutz\SecurityAuditor\Audit\Domain\Model\EntrypointAccessControl;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Model\ProjectFile;

/**
 * Extracts route and access-control metadata from a single entrypoint file.
 * Implementations must degrade silently (return an empty list) when the file
 * cannot be parsed — one broken entrypoint must not abort the mapping stage.
 */
interface EntrypointAccessControlParserInterface
{
    /**
     * @return list<EntrypointAccessControl> one entry per public handler method discovered in the file
     */
    public function parse(ProjectFile $projectFile): array;
}
