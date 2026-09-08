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

use VinceAmstoutz\SecurityAuditor\Audit\Domain\Model\AuthorizationRuleCapability;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Model\ProjectFile;

/**
 * Extracts the attribute and subject vocabulary from a single authorization-rule
 * file — a Symfony voter's `supports()` body, a Laravel policy's methods.
 * Implementations must degrade silently (return null or no entries) when the
 * file cannot be parsed.
 */
interface AuthorizationRuleParserInterface
{
    public function parse(ProjectFile $projectFile): ?AuthorizationRuleCapability;
}
