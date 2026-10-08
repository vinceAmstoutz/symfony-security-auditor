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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Advisory;

use Override;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use RuntimeException;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\AuditedProjectPathHolder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\ComposerAuditRunnerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\DeferredAdvisoryDatabase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\Exception\AdvisorySourceUnavailableException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\LockfileHasher;

final class DeferredAdvisoryDatabaseTest extends TestCase
{
    private string $projectDir;

    /**
     * Proves construction is not eager: if it were, composer audit would run
     * against the holder's default path (before `set()` is ever called), and
     * the `->with('/audited/project')` constraint below would fail.
     */
    public function test_lookup_runs_composer_audit_against_the_path_the_holder_carries_at_call_time(): void
    {
        $composerAuditRunner = $this->createMock(ComposerAuditRunnerInterface::class);
        $composerAuditRunner->expects(self::once())->method('run')->with('/audited/project')->willReturn(
            (string) json_encode(['advisories' => ['vendor/foo' => [['title' => 'Foo advisory', 'affectedVersions' => '>=1.0']]]]),
        );

        $auditedProjectPathHolder = new AuditedProjectPathHolder('/container/default');
        $deferredAdvisoryDatabase = new DeferredAdvisoryDatabase($composerAuditRunner, $auditedProjectPathHolder, new NullLogger(), $this->lockfileHasher(), new MockClock());

        $auditedProjectPathHolder->set('/audited/project');
        $result = $deferredAdvisoryDatabase->lookup('vendor/foo', '1.2.3');

        self::assertCount(1, $result);
    }

    public function test_a_second_lookup_does_not_run_composer_audit_again(): void
    {
        $composerAuditRunner = $this->createMock(ComposerAuditRunnerInterface::class);
        $composerAuditRunner->expects(self::once())->method('run')->willReturn(
            (string) json_encode(['advisories' => []]),
        );

        $deferredAdvisoryDatabase = new DeferredAdvisoryDatabase($composerAuditRunner, new AuditedProjectPathHolder('/proj'), new NullLogger(), $this->lockfileHasher(), new MockClock());

        $deferredAdvisoryDatabase->lookup('vendor/foo', '1.0.0');

        $result = $deferredAdvisoryDatabase->lookup('vendor/bar', '2.0.0');

        self::assertSame([], $result);
    }

    public function test_re_targeting_the_holder_to_a_different_project_reruns_composer_audit_against_the_new_path(): void
    {
        $composerAuditRunner = $this->createMock(ComposerAuditRunnerInterface::class);
        $composerAuditRunner->expects(self::exactly(2))->method('run')->willReturnMap([
            ['/project/a', (string) json_encode(['advisories' => ['vendor/a-pkg' => [['title' => 'A advisory', 'affectedVersions' => '>=1.0']]]])],
            ['/project/b', (string) json_encode(['advisories' => []])],
        ]);

        $auditedProjectPathHolder = new AuditedProjectPathHolder('/container/default');
        $deferredAdvisoryDatabase = new DeferredAdvisoryDatabase($composerAuditRunner, $auditedProjectPathHolder, new NullLogger(), $this->lockfileHasher(), new MockClock());

        $auditedProjectPathHolder->set('/project/a');
        $firstRun = $deferredAdvisoryDatabase->lookup('vendor/a-pkg', '1.2.3');

        $auditedProjectPathHolder->set('/project/b');
        $secondRun = $deferredAdvisoryDatabase->lookup('vendor/b-pkg', '1.0.0');

        self::assertCount(1, $firstRun);
        self::assertSame([], $secondRun);
    }

    public function test_a_load_that_failed_is_not_tried_again_within_the_retry_delay(): void
    {
        $composerAuditRunner = $this->createMock(ComposerAuditRunnerInterface::class);
        $composerAuditRunner->expects(self::once())->method('run')->willThrowException(
            AdvisorySourceUnavailableException::forTimeout(60.0, new RuntimeException('timed out')),
        );
        $mockClock = new MockClock();
        $deferredAdvisoryDatabase = new DeferredAdvisoryDatabase($composerAuditRunner, new AuditedProjectPathHolder('/proj'), new NullLogger(), $this->lockfileHasher(), $mockClock);

        $lookups = [];
        for ($lookup = 0; $lookup < 5; ++$lookup) {
            $lookups[] = $deferredAdvisoryDatabase->lookup('vendor/foo', '1.0.0');
            $mockClock->sleep(1);
        }

        self::assertSame([[], [], [], [], []], $lookups);
    }

    public function test_a_load_that_failed_is_still_not_tried_again_one_second_before_the_retry_delay_ends(): void
    {
        $composerAuditRunner = $this->createMock(ComposerAuditRunnerInterface::class);
        $composerAuditRunner->expects(self::once())->method('run')->willThrowException(AdvisorySourceUnavailableException::forBinaryNotFound());
        $mockClock = new MockClock();
        $deferredAdvisoryDatabase = new DeferredAdvisoryDatabase($composerAuditRunner, new AuditedProjectPathHolder('/proj'), new NullLogger(), $this->lockfileHasher(), $mockClock);

        $deferredAdvisoryDatabase->lookup('vendor/foo', '1.0.0');

        $mockClock->sleep(299);

        self::assertSame([], $deferredAdvisoryDatabase->lookup('vendor/foo', '1.0.0'));
    }

    public function test_a_load_that_failed_is_tried_again_once_the_retry_delay_has_passed(): void
    {
        $composerAuditRunner = $this->createMock(ComposerAuditRunnerInterface::class);
        $composerAuditRunner->expects(self::exactly(2))->method('run')->willReturnOnConsecutiveCalls(
            self::throwException(AdvisorySourceUnavailableException::forBinaryNotFound()),
            $this->advisoryPayloadFor('vendor/foo'),
        );
        $mockClock = new MockClock();
        $deferredAdvisoryDatabase = new DeferredAdvisoryDatabase($composerAuditRunner, new AuditedProjectPathHolder('/proj'), new NullLogger(), $this->lockfileHasher(), $mockClock);

        $duringTheFailure = $deferredAdvisoryDatabase->lookup('vendor/foo', '1.0.0');
        $mockClock->sleep(300);
        $afterTheFailure = $deferredAdvisoryDatabase->lookup('vendor/foo', '1.0.0');

        self::assertSame([], $duringTheFailure);
        self::assertCount(1, $afterTheFailure);
    }

    public function test_a_load_that_failed_is_tried_again_at_once_when_the_lockfile_changes(): void
    {
        file_put_contents($this->projectDir.'/composer.lock', '{"lock": "v1"}');
        $composerAuditRunner = $this->createMock(ComposerAuditRunnerInterface::class);
        $composerAuditRunner->expects(self::exactly(2))->method('run')->willReturnOnConsecutiveCalls(
            self::throwException(AdvisorySourceUnavailableException::forBinaryNotFound()),
            $this->advisoryPayloadFor('vendor/foo'),
        );
        $deferredAdvisoryDatabase = new DeferredAdvisoryDatabase($composerAuditRunner, new AuditedProjectPathHolder($this->projectDir), new NullLogger(), $this->lockfileHasher(), new MockClock());

        $deferredAdvisoryDatabase->lookup('vendor/foo', '1.0.0');
        file_put_contents($this->projectDir.'/composer.lock', '{"lock": "v2"}');

        self::assertCount(1, $deferredAdvisoryDatabase->lookup('vendor/foo', '1.0.0'));
    }

    public function test_a_load_that_failed_is_tried_again_at_once_for_another_project(): void
    {
        $composerAuditRunner = $this->createMock(ComposerAuditRunnerInterface::class);
        $composerAuditRunner->expects(self::exactly(2))->method('run')->willReturnCallback(
            fn (string $projectPath): string => '/project/a' === $projectPath
                ? throw AdvisorySourceUnavailableException::forBinaryNotFound() : $this->advisoryPayloadFor('vendor/b-pkg'),
        );
        $auditedProjectPathHolder = new AuditedProjectPathHolder('/project/a');
        $deferredAdvisoryDatabase = new DeferredAdvisoryDatabase($composerAuditRunner, $auditedProjectPathHolder, new NullLogger(), $this->lockfileHasher(), new MockClock());

        $deferredAdvisoryDatabase->lookup('vendor/b-pkg', '1.0.0');

        $auditedProjectPathHolder->set('/project/b');

        self::assertCount(1, $deferredAdvisoryDatabase->lookup('vendor/b-pkg', '1.0.0'));
    }

    public function test_a_successful_load_is_not_repeated_one_second_before_the_advisory_ttl_ends(): void
    {
        $composerAuditRunner = $this->createMock(ComposerAuditRunnerInterface::class);
        $composerAuditRunner->expects(self::once())->method('run')->willReturn($this->advisoryPayloadFor('vendor/foo'));
        $mockClock = new MockClock();
        $deferredAdvisoryDatabase = new DeferredAdvisoryDatabase($composerAuditRunner, new AuditedProjectPathHolder('/proj'), new NullLogger(), $this->lockfileHasher(), $mockClock);

        $deferredAdvisoryDatabase->lookup('vendor/foo', '1.0.0');

        $mockClock->sleep(86_399);

        self::assertCount(1, $deferredAdvisoryDatabase->lookup('vendor/foo', '1.0.0'));
    }

    public function test_a_successful_load_is_repeated_once_the_advisory_ttl_has_passed(): void
    {
        $composerAuditRunner = $this->createMock(ComposerAuditRunnerInterface::class);
        $composerAuditRunner->expects(self::exactly(2))->method('run')->willReturnOnConsecutiveCalls(
            $this->advisoryPayloadFor('vendor/foo'),
            $this->advisoryPayloadFor('vendor/bar'),
        );
        $mockClock = new MockClock();
        $deferredAdvisoryDatabase = new DeferredAdvisoryDatabase($composerAuditRunner, new AuditedProjectPathHolder('/proj'), new NullLogger(), $this->lockfileHasher(), $mockClock);

        $beforeTheTtl = $deferredAdvisoryDatabase->lookup('vendor/bar', '1.0.0');
        $mockClock->sleep(86_400);
        $afterTheTtl = $deferredAdvisoryDatabase->lookup('vendor/bar', '1.0.0');

        self::assertSame([], $beforeTheTtl);
        self::assertCount(1, $afterTheTtl);
    }

    public function test_a_changed_lockfile_runs_composer_audit_again(): void
    {
        file_put_contents($this->projectDir.'/composer.lock', '{"lock": "v1"}');
        $composerAuditRunner = $this->createMock(ComposerAuditRunnerInterface::class);
        $composerAuditRunner->expects(self::exactly(2))->method('run')->with($this->projectDir)->willReturnOnConsecutiveCalls(
            $this->advisoryPayloadFor('vendor/old'),
            $this->advisoryPayloadFor('vendor/new'),
        );
        $deferredAdvisoryDatabase = new DeferredAdvisoryDatabase($composerAuditRunner, new AuditedProjectPathHolder($this->projectDir), new NullLogger(), $this->lockfileHasher(), new MockClock());

        $beforeTheChange = $deferredAdvisoryDatabase->lookup('vendor/old', '1.0.0');
        file_put_contents($this->projectDir.'/composer.lock', '{"lock": "v2"}');
        $afterTheChange = [
            'old' => $deferredAdvisoryDatabase->lookup('vendor/old', '1.0.0'),
            'new' => $deferredAdvisoryDatabase->lookup('vendor/new', '1.0.0'),
        ];

        self::assertCount(1, $beforeTheChange);
        self::assertSame([], $afterTheChange['old']);
        self::assertCount(1, $afterTheChange['new']);
    }

    public function test_an_unchanged_lockfile_does_not_run_composer_audit_again(): void
    {
        file_put_contents($this->projectDir.'/composer.lock', '{"lock": "v1"}');
        $composerAuditRunner = $this->createMock(ComposerAuditRunnerInterface::class);
        $composerAuditRunner->expects(self::once())->method('run')->willReturn($this->advisoryPayloadFor('vendor/foo'));
        $deferredAdvisoryDatabase = new DeferredAdvisoryDatabase($composerAuditRunner, new AuditedProjectPathHolder($this->projectDir), new NullLogger(), $this->lockfileHasher(), new MockClock());

        $deferredAdvisoryDatabase->lookup('vendor/foo', '1.0.0');

        $second = $deferredAdvisoryDatabase->lookup('vendor/foo', '1.0.0');

        self::assertCount(1, $second);
    }

    #[Override]
    protected function setUp(): void
    {
        $this->projectDir = sys_get_temp_dir().'/deferred_advisory_'.uniqid('', true);
        mkdir($this->projectDir, 0o777, true);
    }

    #[Override]
    protected function tearDown(): void
    {
        (new Filesystem())->remove($this->projectDir);
    }

    private function lockfileHasher(): LockfileHasher
    {
        return new LockfileHasher(new Filesystem(), new NullLogger());
    }

    private function advisoryPayloadFor(string $package): string
    {
        return (string) json_encode(['advisories' => [$package => [['title' => 'Advisory', 'affectedVersions' => '>=1.0']]]]);
    }
}
