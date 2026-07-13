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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Configuration;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileType;

/**
 * A project-defined attacker skill loaded from configuration: an extra expert
 * skill block injected into the attacker prompt whenever a file of its
 * {@see $fileType} appears in the chunk. Lets a project encode team-specific
 * rules ("all queries to LegacyDb must go through SafeQuery") without owning a
 * PHP attacker-skill implementation.
 */
final readonly class CustomAttackerSkill
{
    public function __construct(
        public string $name,
        public ProjectFileType $fileType,
        public string $instructions,
        public int $priority,
    ) {}
}
