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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\CommandLineLimitExceptionInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMRequestTooLargeException;

final class LLMRequestTooLargeExceptionTest extends TestCase
{
    public function test_a_rejection_caused_by_a_command_line_limit_exceeds_the_command_line(): void
    {
        $commandLineLimit = new class('The prompt is longer than one argument can carry.') extends RuntimeException implements CommandLineLimitExceptionInterface {};

        self::assertTrue(LLMRequestTooLargeException::fromProviderRejection($commandLineLimit)->exceedsCommandLine());
    }

    public function test_a_rejection_wrapping_a_command_line_limit_exceeds_the_command_line(): void
    {
        $commandLineLimit = new class('The prompt is longer than one argument can carry.') extends RuntimeException implements CommandLineLimitExceptionInterface {};

        self::assertTrue(LLMRequestTooLargeException::fromProviderRejection(new RuntimeException('The platform failed.', previous: $commandLineLimit))->exceedsCommandLine());
    }

    public function test_a_rejection_by_the_provider_does_not_exceed_the_command_line(): void
    {
        self::assertFalse(LLMRequestTooLargeException::fromProviderRejection(new RuntimeException('prompt is too long', previous: new RuntimeException('HTTP 413')))->exceedsCommandLine());
    }

    public function test_a_refusal_without_a_cause_does_not_exceed_the_command_line(): void
    {
        self::assertFalse((new LLMRequestTooLargeException('prompt is too long'))->exceedsCommandLine());
    }
}
