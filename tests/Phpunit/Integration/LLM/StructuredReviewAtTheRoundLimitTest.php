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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\AI\Platform\Result\MultiPartResult;
use Symfony\AI\Platform\Result\ResultInterface;
use Symfony\AI\Platform\Result\TextResult;
use Symfony\AI\Platform\Result\ToolCall;
use Symfony\AI\Platform\Result\ToolCallResult;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerAgent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerAgentCollaborators;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerModeConfiguration;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolRegistryException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityNarrativeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\CodeLocation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityClassification;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityNarrative;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\NullCoverageRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformBinding;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\SymfonyAiLLMClient;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\ReviewerPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Tool\RecordReviewToolFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\ScriptedResultPlatform;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\RecordingReviewerCache;

final class StructuredReviewAtTheRoundLimitTest extends TestCase
{
    /**
     * @param list<list<int>> $turns the findings the reviewer records on each turn, none for a text answer
     *
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    #[DataProvider('reviewsThatOnlyRecord')]
    public function test_a_verdict_recorded_on_the_last_round_by_a_reviewer_that_reads_nothing_is_cached(int $maxToolIterations, int $batchSize, int $maxConcurrent, array $turns): void
    {
        $findings = $this->findings($batchSize);
        $recordingReviewerCache = new RecordingReviewerCache();

        $reviewed = $this->reviewer($this->recordedVerdicts($findings, $turns), $recordingReviewerCache, new ReviewerModeConfiguration(batchSize: $batchSize, maxToolIterations: $maxToolIterations, maxConcurrent: $maxConcurrent))
            ->review($findings, $this->files($batchSize), new NullCoverageRecorder());

        self::assertSame(
            [$batchSize, $batchSize],
            [\count(array_filter($reviewed, static fn (Vulnerability $vulnerability): bool => $vulnerability->isReviewerValidated())), \count($recordingReviewerCache->stored)],
        );
    }

    /**
     * @return iterable<string, array{int, int, int, list<list<int>>}>
     */
    public static function reviewsThatOnlyRecord(): iterable
    {
        yield 'a single round that records' => [1, 1, 1, [[0]]];
        yield 'a last round that answers after recording' => [2, 1, 1, [[0], []]];
        yield 'a batch recorded one verdict per round' => [4, 5, 1, [[0], [1], [2], [3, 4]]];
        yield 'a concurrent review whose last round answers after recording' => [2, 1, 4, [[0], []]];
    }

    /**
     * @param list<Vulnerability> $findings
     * @param list<list<int>>     $turns
     *
     * @return list<ResultInterface>
     */
    private function recordedVerdicts(array $findings, array $turns): array
    {
        return array_map(static fn (array $turn): ResultInterface => [] === $turn
            ? new MultiPartResult([new TextResult('done')])
            : new MultiPartResult([new ToolCallResult(array_map(
                static fn (int $index): ToolCall => new ToolCall('call-'.$index, 'record_review', ['id' => $findings[$index]->id(), 'accepted' => true, 'reviewer_notes' => 'confirmed']),
                $turn,
            ))]), $turns);
    }

    /**
     * @param list<ResultInterface> $answers
     */
    private function reviewer(array $answers, RecordingReviewerCache $recordingReviewerCache, ReviewerModeConfiguration $reviewerModeConfiguration): ReviewerAgent
    {
        return new ReviewerAgent(
            new ReviewerAgentCollaborators(
                new SymfonyAiLLMClient(new PlatformBinding(new ScriptedResultPlatform($answers), 'm', new NullLogger())),
                new ReviewerPromptBuilder(),
                new NullLogger(),
                new RecordReviewToolFactory(),
                $recordingReviewerCache,
            ),
            $reviewerModeConfiguration,
        );
    }

    /**
     * @return list<Vulnerability>
     *
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    private function findings(int $count): array
    {
        return array_map(static fn (int $index): Vulnerability => Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, 'SQLi '.$index, 0.9),
            new CodeLocation(\sprintf('src/F%d.php', $index), 2, 2),
            new VulnerabilityNarrative('d', 'a', 'p', 'r'),
            'x',
        ), range(0, $count - 1));
    }

    /**
     * @return list<ProjectFile>
     *
     * @throws InvalidProjectFileException
     */
    private function files(int $count): array
    {
        return array_map(static fn (int $index): ProjectFile => ProjectFile::create(
            \sprintf('src/F%d.php', $index),
            \sprintf('/app/src/F%d.php', $index),
            "<?php\n\$db->query(\$_GET['q']);\n",
        ), range(0, $count - 1));
    }
}
