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
}
