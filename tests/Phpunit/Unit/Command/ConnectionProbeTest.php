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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Command;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ConnectionProbe;

final class ConnectionProbeTest extends TestCase
{
    public function test_it_names_the_failure_of_a_request_the_provider_refused(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willThrowException(new LLMProviderException('HTTP 401: invalid x-api-key'));

        self::assertSame('HTTP 401: invalid x-api-key', (new ConnectionProbe())->failureReason($llmClient));
    }

    public function test_it_names_an_answer_the_provider_cut_short(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturn(LLMResponse::of('', 'gpt-x', 'empty_content', TokenUsageSnapshot::zero()));

        self::assertSame('The provider answered, but its answer ended early (empty_content).', (new ConnectionProbe())->failureReason($llmClient));
    }

    /**
     * @throws InvalidTokenUsageException
     */
    public function test_it_reports_no_failure_for_a_provider_that_answered(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturn(LLMResponse::of('OK', 'gpt-x', 'stop', TokenUsageSnapshot::of(12, 1)));

        self::assertNull((new ConnectionProbe())->failureReason($llmClient));
    }
}
