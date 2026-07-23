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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\SelfUpdate;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\ThrottledUpdateAvailabilityNotifier;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\UpdateCheckState;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\SelfUpdate\Fixture\FakeSelfUpdater;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\SelfUpdate\Fixture\InMemoryUpdateCheckStore;

final class ThrottledUpdateAvailabilityNotifierTest extends TestCase
{
    private const string EXPECTED_NOTICE = 'A new version (2.0.0) is available. Run "symfony-security-auditor self-update" to upgrade.';

    public function test_it_reports_a_newer_version_as_available(): void
    {
        $throttledUpdateAvailabilityNotifier = new ThrottledUpdateAvailabilityNotifier(
            new FakeSelfUpdater('2.0.0'),
            new InMemoryUpdateCheckStore(),
            new MockClock('2026-01-01 00:00:00'),
        );

        self::assertSame(self::EXPECTED_NOTICE, $throttledUpdateAvailabilityNotifier->availableUpdateNotice('1.0.0'));
    }

    public function test_it_reports_no_notice_when_already_on_the_latest_version(): void
    {
        $throttledUpdateAvailabilityNotifier = new ThrottledUpdateAvailabilityNotifier(
            new FakeSelfUpdater('1.0.0'),
            new InMemoryUpdateCheckStore(),
            new MockClock('2026-01-01 00:00:00'),
        );

        self::assertNull($throttledUpdateAvailabilityNotifier->availableUpdateNotice('1.0.0'));
    }

    public function test_it_reports_no_notice_when_the_running_version_is_newer(): void
    {
        $throttledUpdateAvailabilityNotifier = new ThrottledUpdateAvailabilityNotifier(
            new FakeSelfUpdater('1.0.0'),
            new InMemoryUpdateCheckStore(),
            new MockClock('2026-01-01 00:00:00'),
        );

        self::assertNull($throttledUpdateAvailabilityNotifier->availableUpdateNotice('2.0.0'));
    }

    public function test_it_performs_a_check_only_lookup(): void
    {
        $fakeSelfUpdater = new FakeSelfUpdater('2.0.0');

        (new ThrottledUpdateAvailabilityNotifier($fakeSelfUpdater, new InMemoryUpdateCheckStore(), new MockClock('2026-01-01 00:00:00')))
            ->availableUpdateNotice('1.0.0');

        self::assertTrue($fakeSelfUpdater->lastCheckOnly);
    }

    #[DataProvider('nonReleaseVersions')]
    public function test_it_skips_the_network_check_for_a_non_release_version(string $currentVersion): void
    {
        $fakeSelfUpdater = new FakeSelfUpdater('2.0.0');

        (new ThrottledUpdateAvailabilityNotifier($fakeSelfUpdater, new InMemoryUpdateCheckStore(), new MockClock('2026-01-01 00:00:00')))
            ->availableUpdateNotice($currentVersion);

        self::assertSame(0, $fakeSelfUpdater->calls);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function nonReleaseVersions(): iterable
    {
        yield 'unknown sentinel' => ['unknown'];
        yield 'development branch' => ['dev-main'];
        yield 'two-segment version' => ['1.0'];
    }

    public function test_it_returns_no_notice_when_the_check_fails_without_a_cached_answer(): void
    {
        $throttledUpdateAvailabilityNotifier = new ThrottledUpdateAvailabilityNotifier(
            new FakeSelfUpdater(throws: true),
            new InMemoryUpdateCheckStore(),
            new MockClock('2026-01-01 00:00:00'),
        );

        self::assertNull($throttledUpdateAvailabilityNotifier->availableUpdateNotice('1.0.0'));
    }

    public function test_it_falls_back_to_the_cached_version_when_the_check_fails(): void
    {
        $mockClock = new MockClock('2026-01-01 00:00:00');
        $throttledUpdateAvailabilityNotifier = new ThrottledUpdateAvailabilityNotifier(
            new FakeSelfUpdater(throws: true),
            new InMemoryUpdateCheckStore(new UpdateCheckState($mockClock->now()->modify('-2 days'), '2.0.0')),
            $mockClock,
        );

        self::assertSame(self::EXPECTED_NOTICE, $throttledUpdateAvailabilityNotifier->availableUpdateNotice('1.0.0'));
    }

    public function test_it_serves_the_cached_version_just_under_the_daily_throttle_window(): void
    {
        $mockClock = new MockClock('2026-01-01 00:00:00');
        $fakeSelfUpdater = new FakeSelfUpdater('2.0.0');
        $throttledUpdateAvailabilityNotifier = new ThrottledUpdateAvailabilityNotifier($fakeSelfUpdater, new InMemoryUpdateCheckStore(), $mockClock);

        $throttledUpdateAvailabilityNotifier->availableUpdateNotice('1.0.0');

        $fakeSelfUpdater->latestVersion = '3.0.0';
        $mockClock->sleep(86_399);

        self::assertSame(self::EXPECTED_NOTICE, $throttledUpdateAvailabilityNotifier->availableUpdateNotice('1.0.0'));
    }

    public function test_it_re_checks_once_the_daily_throttle_window_elapses(): void
    {
        $mockClock = new MockClock('2026-01-01 00:00:00');
        $fakeSelfUpdater = new FakeSelfUpdater('2.0.0');
        $throttledUpdateAvailabilityNotifier = new ThrottledUpdateAvailabilityNotifier($fakeSelfUpdater, new InMemoryUpdateCheckStore(), $mockClock);

        $throttledUpdateAvailabilityNotifier->availableUpdateNotice('1.0.0');

        $fakeSelfUpdater->latestVersion = '3.0.0';
        $mockClock->sleep(86_400);

        self::assertSame(
            'A new version (3.0.0) is available. Run "symfony-security-auditor self-update" to upgrade.',
            $throttledUpdateAvailabilityNotifier->availableUpdateNotice('1.0.0'),
        );
    }
}
