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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Domain\Model;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ArchitectureStyle;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectProfile;

final class ProjectProfileTest extends TestCase
{
    public function test_a_profile_read_from_no_lockfile_satisfies_every_requirement(): void
    {
        self::assertTrue(ProjectProfile::unknown()->satisfies('symfony>=8.2 symfony/ai-agent'));
    }

    public function test_a_package_the_lockfile_does_not_install_is_not_satisfied(): void
    {
        self::assertFalse(ProjectProfile::of(['symfony/http-kernel' => 'v8.1.4'], [])->satisfies('symfony/ai-agent'));
    }

    public function test_any_installed_alternative_satisfies_a_requirement(): void
    {
        self::assertTrue(ProjectProfile::of(['openai-php/client' => 'v0.10.1'], [])->satisfies('symfony/ai-agent|openai-php/client'));
    }

    public function test_every_space_separated_term_must_hold(): void
    {
        self::assertFalse(ProjectProfile::of(['symfony/messenger' => 'v8.1.0'], [])->satisfies('symfony/messenger symfony/webhook'));
    }

    public function test_a_requirement_holds_when_each_of_its_terms_does(): void
    {
        self::assertTrue(ProjectProfile::of(['symfony/messenger' => 'v8.1.0', 'symfony/webhook' => 'v8.1.0'], [])->satisfies('symfony/messenger symfony/webhook'));
    }

    public function test_a_locked_symfony_release_at_or_above_the_minimum_satisfies_a_version_requirement(): void
    {
        self::assertTrue(ProjectProfile::of(['symfony/http-kernel' => 'v8.2.0'], [])->satisfies('symfony>=8.2'));
    }

    public function test_a_locked_development_branch_counts_as_its_release(): void
    {
        self::assertTrue(ProjectProfile::of(['symfony/http-kernel' => '8.2.x-dev'], [])->satisfies('symfony>=8.2'));
    }

    #[DataProvider('branchesNamingNoRelease')]
    public function test_a_kernel_locked_at_a_branch_naming_no_release_keeps_the_symfony_hunts(string $lockedVersion): void
    {
        self::assertTrue(ProjectProfile::of(['symfony/http-kernel' => $lockedVersion], [])->satisfies('symfony>=8.2'));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function branchesNamingNoRelease(): iterable
    {
        yield 'the main branch' => ['dev-main'];
        yield 'a feature branch mentioning an older release' => ['dev-fix-8.1-session'];
    }

    /**
     * @param array<string, string> $installedPackages
     */
    #[DataProvider('lockfilesBelowTheMinimum')]
    public function test_a_lockfile_without_a_recent_enough_symfony_does_not_satisfy_a_version_requirement(array $installedPackages): void
    {
        self::assertFalse(ProjectProfile::of($installedPackages, [])->satisfies('symfony>=8.2'));
    }

    /**
     * @return iterable<string, array{array<string, string>}>
     */
    public static function lockfilesBelowTheMinimum(): iterable
    {
        yield 'an older release' => [['symfony/http-kernel' => 'v8.1.4']];
        yield 'no kernel at all' => [['monolog/monolog' => '3.9.0']];
    }

    public function test_a_profile_read_from_no_lockfile_leaves_cache_keys_alone(): void
    {
        self::assertSame('', ProjectProfile::unknown()->signature());
    }

    public function test_installing_another_package_changes_the_signature(): void
    {
        self::assertNotSame(
            ProjectProfile::of(['symfony/http-kernel' => 'v8.2.0'], [])->signature(),
            ProjectProfile::of(['symfony/http-kernel' => 'v8.2.0', 'symfony/ai-agent' => 'v0.15.0'], [])->signature(),
        );
    }

    public function test_the_order_the_lockfile_lists_packages_in_keeps_the_signature(): void
    {
        self::assertSame(
            ProjectProfile::of(['symfony/http-kernel' => 'v8.2.0', 'doctrine/orm' => '3.5.0'], [])->signature(),
            ProjectProfile::of(['doctrine/orm' => '3.5.0', 'symfony/http-kernel' => 'v8.2.0'], [])->signature(),
        );
    }

    public function test_moving_to_another_symfony_minor_release_changes_the_signature(): void
    {
        self::assertNotSame(
            ProjectProfile::of(['symfony/http-kernel' => 'v8.1.9'], [])->signature(),
            ProjectProfile::of(['symfony/http-kernel' => 'v8.2.0'], [])->signature(),
        );
    }

    public function test_patch_releases_keep_the_signature(): void
    {
        self::assertSame(
            ProjectProfile::of(['symfony/http-kernel' => 'v8.2.0', 'monolog/monolog' => '3.8.0'], [])->signature(),
            ProjectProfile::of(['symfony/http-kernel' => 'v8.2.3', 'monolog/monolog' => '3.9.1'], [])->signature(),
        );
    }

    public function test_another_architecture_changes_the_signature(): void
    {
        self::assertNotSame(
            ProjectProfile::of(['symfony/http-kernel' => 'v8.2.0'], [])->signature(),
            ProjectProfile::of(['symfony/http-kernel' => 'v8.2.0'], [ArchitectureStyle::CQRS])->signature(),
        );
    }

    public function test_a_layout_read_without_a_lockfile_still_changes_the_signature(): void
    {
        self::assertNotSame('', ProjectProfile::of(null, [ArchitectureStyle::CQRS])->signature());
    }

    public function test_no_lockfile_and_a_lockfile_listing_nothing_sign_differently(): void
    {
        self::assertNotSame(
            ProjectProfile::of(null, [ArchitectureStyle::CQRS])->signature(),
            ProjectProfile::of([], [ArchitectureStyle::CQRS])->signature(),
        );
    }

    public function test_other_bounded_contexts_change_the_signature(): void
    {
        self::assertNotSame(
            ProjectProfile::of(null, [ArchitectureStyle::BOUNDED_CONTEXTS], ['Billing', 'Identity'])->signature(),
            ProjectProfile::of(null, [ArchitectureStyle::BOUNDED_CONTEXTS], ['Billing', 'Shipping'])->signature(),
        );
    }
}
