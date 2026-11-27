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

use Exception;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolRegistryException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityNarrativeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\CodeLocation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityClassification;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityNarrative;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\ReviewerAgentHarness;

final class ReviewerAgentFileGroupTest extends TestCase
{
    /**
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidProjectFileException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    public function test_the_findings_of_one_file_are_reviewed_in_one_call_that_carries_the_file_once(): void
    {
        $userMessages = [];
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturnCallback(static function (string $system, string $user) use (&$userMessages): LLMResponse {
            $userMessages[] = $user;

            return self::verdicts($user, true);
        });

        $reviewed = ReviewerAgentHarness::reviewerAgent($llmClient)->reviewByFile(
            [$this->findingAt('src/A.php', 1), $this->findingAt('src/B.php', 1), $this->findingAt('src/A.php', 2)],
            [ProjectFile::create('src/A.php', '/app/src/A.php', "<?php\n// UNIQUE-A-SOURCE\n"), ProjectFile::create('src/B.php', '/app/src/B.php', '<?php')],
            AuditContext::forProject(sys_get_temp_dir()),
            false,
            null,
        );

        self::assertCount(2, $userMessages);
        self::assertSame(1, substr_count(implode("\n", $userMessages), 'UNIQUE-A-SOURCE'));
        self::assertSame([true, true, true], array_map(static fn (Vulnerability $vulnerability): bool => $vulnerability->isReviewerValidated(), $reviewed));
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    public function test_each_verdict_of_interleaved_files_goes_to_its_own_finding(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturnCallback(static fn (string $system, string $user): LLMResponse => self::verdicts($user, str_contains($user, 'src/A.php')));
        $findings = [$this->findingAt('src/A.php', 1), $this->findingAt('src/B.php', 1), $this->findingAt('src/A.php', 2), $this->findingAt('src/B.php', 2)];

        $reviewed = ReviewerAgentHarness::reviewerAgent($llmClient)->reviewByFile($findings, [], AuditContext::forProject(sys_get_temp_dir()), false, null);

        self::assertSame(
            [['src/A.php', 1, true], ['src/B.php', 1, false], ['src/A.php', 2, true], ['src/B.php', 2, false]],
            array_map(static fn (Vulnerability $vulnerability): array => [$vulnerability->filePath(), $vulnerability->lineStart(), $vulnerability->isReviewerValidated()], $reviewed),
        );
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    public function test_a_file_with_more_findings_than_one_call_holds_is_reviewed_in_several(): void
    {
        $calls = 0;
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturnCallback(static function (string $system, string $user) use (&$calls): LLMResponse {
            ++$calls;

            return self::verdicts($user, true);
        });

        ReviewerAgentHarness::reviewerAgent($llmClient)->reviewByFile(
            array_map(fn (int $line): Vulnerability => $this->findingAt('src/A.php', $line), range(1, 21)),
            [],
            AuditContext::forProject(sys_get_temp_dir()),
            false,
            null,
        );

        self::assertSame(2, $calls);
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidToolRegistryException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    #[DataProvider('abortCases')]
    public function test_an_abort_before_the_grouped_calls_marks_their_findings_unreached(Exception $exception, string $status): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willThrowException($exception);
        $auditContext = AuditContext::forProject(sys_get_temp_dir());

        $aborted = false;
        try {
            ReviewerAgentHarness::reviewerAgent($llmClient)->reviewByFile(
                [$this->findingAt('src/C.php', 1), $this->findingAt('src/A.php', 1), $this->findingAt('src/A.php', 2)],
                [],
                $auditContext,
                false,
                null,
            );
        } catch (BudgetExceededException|LLMProviderException) {
            $aborted = true;
        }

        self::assertTrue($aborted, 'The reviewer must rethrow the abort.');
        self::assertSame(
            [
                ['stage' => 'reviewer', 'file' => 'src/C.php', 'status' => $status],
                ['stage' => 'reviewer', 'file' => 'src/A.php', 'status' => $status],
                ['stage' => 'reviewer', 'file' => 'src/A.php', 'status' => $status],
            ],
            $auditContext->coverage(),
        );
    }

    /** @return iterable<string, array{Exception, string}> */
    public static function abortCases(): iterable
    {
        yield 'budget exceeded' => [BudgetExceededException::forTokens(500, 100), 'aborted'];
        yield 'provider failure' => [new LLMProviderException('platform unreachable'), 'errored'];
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    private function findingAt(string $filePath, int $line): Vulnerability
    {
        return Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, \sprintf('Static analysis at %s:%d', $filePath, $line), 0.8),
            new CodeLocation($filePath, $line, $line),
            new VulnerabilityNarrative('d', 'a', 'p', 'r'),
            'c',
        );
    }

    /**
     * Answers every finding id the batch message lists, or the bare verdict a
     * single-finding message expects.
     *
     * @throws InvalidTokenUsageException
     */
    private static function verdicts(string $userMessage, bool $accepted): LLMResponse
    {
        preg_match_all('/^ID: (\S+)$/m', $userMessage, $matches);
        $answer = str_contains($userMessage, '### Finding 1')
            ? array_map(static fn (string $id): array => ['id' => $id, 'accepted' => $accepted], $matches[1])
            : ['accepted' => $accepted];

        return LLMResponse::of((string) json_encode($answer), 'test', 'end_turn', TokenUsageSnapshot::of(0, 0));
    }
}
