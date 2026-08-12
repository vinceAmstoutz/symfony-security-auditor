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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Chunk;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunk\ChunkContextKeyDeriver;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AccessControlMap;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileInventory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;

final class ChunkContextKeyDeriverTest extends TestCase
{
    public function test_it_does_not_collide_when_a_firewall_rule_shifts_across_another_rules_boundary(): void
    {
        $chunkContextKeyDeriver = new ChunkContextKeyDeriver();

        $symfonyMapping = SymfonyMapping::of(
            ProjectFileInventory::fromGroups([]),
            new AccessControlMap(firewallRules: ['ab', 'c']),
        );
        $shifted = SymfonyMapping::of(
            ProjectFileInventory::fromGroups([]),
            new AccessControlMap(firewallRules: ['a', 'bc']),
        );

        self::assertNotSame(
            $chunkContextKeyDeriver->derive('', '', '', $symfonyMapping),
            $chunkContextKeyDeriver->derive('', '', '', $shifted),
        );
    }
}
