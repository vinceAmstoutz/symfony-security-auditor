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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Domain\Exception;

use PHPUnit\Framework\TestCase;
use RuntimeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\GitChangedFilesUnavailableException;

final class GitChangedFilesUnavailableExceptionTest extends TestCase
{
    public function test_from_process_failure_includes_the_trimmed_stderr_and_wraps_the_cause(): void
    {
        $runtimeException = new RuntimeException('process boom');

        $gitChangedFilesUnavailableException = GitChangedFilesUnavailableException::fromProcessFailure('main', "  fatal: bad revision\n", $runtimeException);

        self::assertSame('git diff against "main" failed: fatal: bad revision', $gitChangedFilesUnavailableException->getMessage());
        self::assertSame($runtimeException, $gitChangedFilesUnavailableException->getPrevious());
        self::assertSame(0, $gitChangedFilesUnavailableException->getCode());
    }

    public function test_from_process_failure_falls_back_to_unknown_error_when_stderr_is_blank(): void
    {
        $gitChangedFilesUnavailableException = GitChangedFilesUnavailableException::fromProcessFailure('origin/main', "   \n", new RuntimeException('boom'));

        self::assertSame('git diff against "origin/main" failed: unknown error', $gitChangedFilesUnavailableException->getMessage());
    }

    public function test_for_refused_repository_names_the_project_and_passes_on_the_trimmed_reason_git_gave(): void
    {
        $gitChangedFilesUnavailableException = GitChangedFilesUnavailableException::forRefusedRepository('/srv/app', "  fatal: detected dubious ownership in repository at '/srv/app'\n");

        self::assertSame('Git refused the repository of "/srv/app": fatal: detected dubious ownership in repository at \'/srv/app\'', $gitChangedFilesUnavailableException->getMessage());
        self::assertSame(0, $gitChangedFilesUnavailableException->getCode());
        self::assertNull($gitChangedFilesUnavailableException->getPrevious());
    }

    public function test_for_refused_repository_falls_back_to_unknown_error_when_git_said_nothing(): void
    {
        $gitChangedFilesUnavailableException = GitChangedFilesUnavailableException::forRefusedRepository('/srv/app', "   \n");

        self::assertSame('Git refused the repository of "/srv/app": unknown error', $gitChangedFilesUnavailableException->getMessage());
    }

    public function test_for_process_failure_names_the_operation_and_wraps_the_cause(): void
    {
        $runtimeException = new RuntimeException('timed out');

        $gitChangedFilesUnavailableException = GitChangedFilesUnavailableException::forProcessFailure('verify git ref "main"', $runtimeException);

        self::assertSame('Could not verify git ref "main": timed out', $gitChangedFilesUnavailableException->getMessage());
        self::assertSame($runtimeException, $gitChangedFilesUnavailableException->getPrevious());
        self::assertSame(0, $gitChangedFilesUnavailableException->getCode());
    }
}
