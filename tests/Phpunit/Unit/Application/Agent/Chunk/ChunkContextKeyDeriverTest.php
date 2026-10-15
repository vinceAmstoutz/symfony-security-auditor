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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ApplicationAccessControl;
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
            $chunkContextKeyDeriver->derive('', '', '', '', $symfonyMapping),
            $chunkContextKeyDeriver->derive('', '', '', '', $shifted),
        );
    }

    public function test_the_configuration_files_the_mapping_could_not_read_change_the_key(): void
    {
        self::assertNotSame($this->keyFor(['main'], []), $this->keyFor(['main'], ['config/packages/security.yaml']));
        self::assertNotSame($this->keyFor(['main'], ['config/packages/security.yaml']), $this->keyFor(['main'], ['config/packages/app.yaml']));
        self::assertNotSame($this->keyFor(['config/packages/security.yaml'], []), $this->keyFor([], ['config/packages/security.yaml']));
    }

    public function test_the_rules_and_firewalls_of_each_application_change_the_key(): void
    {
        $keys = [
            $this->keyForApplications([]),
            $this->keyForApplications(['apps/api/' => new ApplicationAccessControl(['^/a' => ['ROLE_A']], [])]),
            $this->keyForApplications(['apps/api/' => new ApplicationAccessControl(['^/a' => ['ROLE_B']], [])]),
            $this->keyForApplications(['apps/web/' => new ApplicationAccessControl(['^/a' => ['ROLE_A']], [])]),
            $this->keyForApplications(['apps/api/' => new ApplicationAccessControl([], ['^/a=ROLE_A'])]),
            $this->keyForApplications(['apps/api/' => new ApplicationAccessControl([], ['main'])]),
            $this->keyForApplications(['apps/api/' => new ApplicationAccessControl(['^/a' => ['ROLE_A']], ['main'])]),
            $this->keyForApplications(['apps/api/' => new ApplicationAccessControl(['^/a' => ['ROLE_A']], ['other'])]),
            $this->keyForApplications(['apps/api/' => new ApplicationAccessControl(['^/a' => ['ROLE_A'], '^/b' => ['ROLE_B']], [])]),
        ];

        self::assertSame($keys, array_values(array_unique($keys)));
    }

    public function test_the_candidate_preamble_alone_yields_a_key_of_its_own(): void
    {
        $chunkContextKeyDeriver = new ChunkContextKeyDeriver();
        $symfonyMapping = SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap());

        $withCandidates = $chunkContextKeyDeriver->derive('', '', '', 'candidate preamble', $symfonyMapping);

        self::assertNotSame('', $withCandidates);
        self::assertNotSame($chunkContextKeyDeriver->derive('', '', '', 'other candidate preamble', $symfonyMapping), $withCandidates);
        self::assertNotSame($chunkContextKeyDeriver->derive('', '', 'candidate preamble', '', $symfonyMapping), $withCandidates);
    }

    public function test_the_key_hashes_each_preamble_in_order_with_the_candidate_preamble_before_the_mapping_fingerprint(): void
    {
        $symfonyMapping = SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap());

        $key = (new ChunkContextKeyDeriver())->derive('markers', 'rejected', 'previous', 'candidates', $symfonyMapping);

        self::assertSame(
            hash('sha256', hash('sha256', 'markers').hash('sha256', 'rejected').hash('sha256', 'previous').hash('sha256', 'candidates').hash('sha256', '')),
            $key,
        );
    }

    public function test_without_candidates_the_key_is_the_one_earlier_releases_derived_so_their_cache_entries_still_hit(): void
    {
        $symfonyMapping = SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap());

        $key = (new ChunkContextKeyDeriver())->derive('markers', 'rejected', 'previous', '', $symfonyMapping);

        self::assertSame(
            hash('sha256', hash('sha256', 'markers').hash('sha256', 'rejected').hash('sha256', 'previous').hash('sha256', '')),
            $key,
        );
    }

    public function test_the_mapping_fingerprint_is_remembered_per_mapping_instance_and_still_tells_mappings_apart(): void
    {
        $chunkContextKeyDeriver = new ChunkContextKeyDeriver();
        $symfonyMapping = SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap(firewallRules: ['^/admin']));
        $otherMapping = SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap(firewallRules: ['^/api']));

        $firstChunkKey = $chunkContextKeyDeriver->derive('', '', '', '', $symfonyMapping);
        $secondChunkKey = $chunkContextKeyDeriver->derive('', '', '', '', $symfonyMapping);

        self::assertSame($firstChunkKey, $secondChunkKey);
        self::assertSame(hash('sha256', hash('sha256', '').hash('sha256', '').hash('sha256', '').hash('sha256', hash('sha256', hash('sha256', '^/admin')))), $firstChunkKey);
        self::assertNotSame($firstChunkKey, $chunkContextKeyDeriver->derive('', '', '', '', $otherMapping));
    }

    /**
     * @param list<string> $firewallRules
     * @param list<string> $unreadableConfigurationFiles
     */
    private function keyFor(array $firewallRules, array $unreadableConfigurationFiles): string
    {
        return (new ChunkContextKeyDeriver())->derive('', '', '', '', SymfonyMapping::of(
            ProjectFileInventory::fromGroups([]),
            new AccessControlMap(firewallRules: $firewallRules, unreadableConfigurationFiles: $unreadableConfigurationFiles),
        ));
    }

    /**
     * @param array<string, ApplicationAccessControl> $applicationAccessControls
     */
    private function keyForApplications(array $applicationAccessControls): string
    {
        return (new ChunkContextKeyDeriver())->derive('', '', '', '', SymfonyMapping::of(
            ProjectFileInventory::fromGroups([]),
            new AccessControlMap(firewallRules: ['main'], applicationAccessControls: $applicationAccessControls),
        ));
    }
}
