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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunking;

/** @internal not part of the BC promise — see docs/versioning.md */
enum ChunkingStrategy: string
{
    /**
     * Groups files by feature: the controller, its entity, its repository,
     * its form, its voter, and related templates land in the same chunk so
     * the LLM can follow cross-file data flow.
     */
    case Feature = 'feature';

    /**
     * Sorts files by attack-surface priority (controller > authenticator >
     * voter > … > template > config > php) and chunks them in fixed-size
     * windows. Preserves the pre-feature-chunking behaviour.
     */
    case Type = 'type';
}
