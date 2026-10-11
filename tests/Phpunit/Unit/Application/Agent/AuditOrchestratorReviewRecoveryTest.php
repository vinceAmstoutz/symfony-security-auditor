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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\AuditOrchestratorHarness;

final class AuditOrchestratorReviewRecoveryTest extends TestCase
{
    private const string FILE = 'src/Controller/Foo.php';

    /**
     * @throws InvalidTokenUsageException
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    public function test_a_review_failure_that_a_later_iteration_recovers_does_not_leave_the_report_incomplete(): void
    {
        $auditReport = $this->audit([$this->noVerdict(), $this->verdict(true)]);

        self::assertCount(1, $auditReport->vulnerabilities());
        self::assertSame([], $auditReport->unanalyzedFiles());
        self::assertTrue($auditReport->isComplete());
        self::assertSame([], $this->coverageWithStatus($auditReport, 'errored'));
    }

    /**
     * @throws InvalidTokenUsageException
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    public function test_a_review_failure_that_a_later_rejection_settles_does_not_leave_the_report_incomplete(): void
    {
        $auditReport = $this->audit([$this->noVerdict(), $this->verdict(false)]);

        self::assertSame([], $auditReport->vulnerabilities());
        self::assertSame([], $auditReport->unanalyzedFiles());
        self::assertTrue($auditReport->isComplete());
    }

    /**
     * @throws InvalidTokenUsageException
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    public function test_a_review_failure_that_no_iteration_recovers_keeps_the_report_incomplete(): void
    {
        $auditReport = $this->audit([$this->noVerdict(), $this->noVerdict(), $this->noVerdict()]);

        self::assertSame([self::FILE], $auditReport->unanalyzedFiles());
        self::assertFalse($auditReport->isComplete());
    }

    /**
     * @param list<LLMResponse> $reviewerAnswers answered in turn, the last one for every review after them
     *
     * @throws InvalidTokenUsageException
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    private function audit(array $reviewerAnswers): AuditReport
    {
        $attackerLlm = self::createStub(LLMClientInterface::class);
        $attackerLlm->method('complete')->willReturn(AuditOrchestratorHarness::attackerResponse([
            AuditOrchestratorHarness::vulnerabilityPayload(title: 'SQLi', filePath: self::FILE),
        ]));
        $reviewerLlm = self::createStub(LLMClientInterface::class);
        $reviewerLlm->method('complete')->willReturnCallback(
            static function () use (&$reviewerAnswers): LLMResponse {
                return \count($reviewerAnswers) > 1 ? array_shift($reviewerAnswers) : $reviewerAnswers[0];
            },
        );

        $auditContext = AuditOrchestratorHarness::contextWithMapping(sys_get_temp_dir());
        AuditOrchestratorHarness::orchestrator($attackerLlm, $reviewerLlm, ['maxIterations' => 3])->orchestrate($auditContext);

        return AuditReport::fromContext($auditContext);
    }

    /**
     * @throws InvalidTokenUsageException
     */
    private function noVerdict(): LLMResponse
    {
        return LLMResponse::of((string) json_encode(['reviewer_notes' => 'not sure']), 'test', 'end_turn', TokenUsageSnapshot::of(0, 0));
    }

    /**
     * @throws InvalidTokenUsageException
     */
    private function verdict(bool $accepted): LLMResponse
    {
        return LLMResponse::of((string) json_encode(['accepted' => $accepted]), 'test', 'end_turn', TokenUsageSnapshot::of(0, 0));
    }

    /**
     * @return list<array{stage: string, file: string, status: string}>
     */
    private function coverageWithStatus(AuditReport $auditReport, string $status): array
    {
        return array_values(array_filter(
            $auditReport->coverage(),
            static fn (array $entry): bool => $entry['status'] === $status,
        ));
    }
}
