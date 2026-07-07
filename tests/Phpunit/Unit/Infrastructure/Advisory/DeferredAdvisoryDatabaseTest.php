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

use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\AuditedProjectPathHolder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\ComposerAuditRunnerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\DeferredAdvisoryDatabase;

final class DeferredAdvisoryDatabaseTest extends TestCase
{
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
        $deferredAdvisoryDatabase = new DeferredAdvisoryDatabase($composerAuditRunner, $auditedProjectPathHolder, new NullLogger());

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

        $deferredAdvisoryDatabase = new DeferredAdvisoryDatabase($composerAuditRunner, new AuditedProjectPathHolder('/proj'), new NullLogger());

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
        $deferredAdvisoryDatabase = new DeferredAdvisoryDatabase($composerAuditRunner, $auditedProjectPathHolder, new NullLogger());

        $auditedProjectPathHolder->set('/project/a');
        $firstRun = $deferredAdvisoryDatabase->lookup('vendor/a-pkg', '1.2.3');

        $auditedProjectPathHolder->set('/project/b');
        $secondRun = $deferredAdvisoryDatabase->lookup('vendor/b-pkg', '1.0.0');

        self::assertCount(1, $firstRun);
        self::assertSame([], $secondRun);
    }
}
