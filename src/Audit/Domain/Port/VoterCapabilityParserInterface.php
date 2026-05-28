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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VoterCapability;

/**
 * Extracts the attribute and subject vocabulary from a single voter file by
 * scanning the body of its `supports()` method. Implementations must degrade
 * silently (return null or no entries) when the file cannot be parsed.
 */
interface VoterCapabilityParserInterface
{
    public function parse(ProjectFile $projectFile): ?VoterCapability;
}
