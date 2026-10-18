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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\RiskMarkerIndex;
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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\NullAttackerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformBinding;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\SymfonyAiLLMClient;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\ReviewerPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\CountingReadingTool;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\ScriptedResultPlatform;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\ToolCallCounter;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\UnmarkedRecordReviewToolFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\UnmarkedRecordVulnerabilityToolFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Chunk\Fixture\ChunkAnalysisInputs;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Chunk\Fixture\SequentialChunkAnalyzerHarness;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\RecordingReviewerCache;

final class UnmarkedRecordingToolAtTheRoundLimitTest extends TestCase
{
    /**
     * @throws InvalidToolRegistryException
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    public function test_a_finding_a_custom_factorys_unmarked_tool_records_on_the_last_round_is_kept(): void
    {
        $scriptedResultPlatform = new ScriptedResultPlatform([
            $this->callOf('read_file', []),
            $this->callOf('read_file', []),
            $this->callOf('record_vulnerability', SequentialChunkAnalyzerHarness::finding('SQLi recorded on the last round')),
            new MultiPartResult([new TextResult('Done.')]),
        ]);

        [$vulnerabilities] = SequentialChunkAnalyzerHarness::analyzerRecordingThrough($this->client($scriptedResultPlatform), new NullAttackerCache(), new UnmarkedRecordVulnerabilityToolFactory())
            ->analyze([[ChunkAnalysisInputs::file('src/A.php')]], ChunkAnalysisInputs::request(), new NullCoverageRecorder(), new ToolRegistry([new CountingReadingTool('read_file', new ToolCallCounter())], new NullLogger()), new RiskMarkerIndex([]));

        self::assertSame(['SQLi recorded on the last round'], array_map(static fn (Vulnerability $vulnerability): string => $vulnerability->title(), $vulnerabilities));
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function test_a_verdict_a_custom_factorys_unmarked_tool_records_on_the_only_round_is_applied_and_cached(): void
    {
        $vulnerability = Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, 'SQLi', 0.9),
            new CodeLocation('src/A.php', 2, 2),
            new VulnerabilityNarrative('d', 'a', 'p', 'r'),
            'x',
        );
        $recordingReviewerCache = new RecordingReviewerCache();
        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators(
                $this->client(new ScriptedResultPlatform([$this->callOf('record_review', ['id' => $vulnerability->id(), 'accepted' => true, 'reviewer_notes' => 'confirmed'])])),
                new ReviewerPromptBuilder(),
                new NullLogger(),
                new UnmarkedRecordReviewToolFactory(),
                $recordingReviewerCache,
            ),
            new ReviewerModeConfiguration(maxToolIterations: 1),
        );

        $reviewed = $reviewerAgent->review([$vulnerability], [ProjectFile::create('src/A.php', '/app/src/A.php', "<?php\n\$db->query(\$_GET['q']);\n")], new NullCoverageRecorder());

        self::assertSame([[true], 1], [array_map(static fn (Vulnerability $reviewedVulnerability): bool => $reviewedVulnerability->isReviewerValidated(), $reviewed), \count($recordingReviewerCache->stored)]);
    }

    private function client(ScriptedResultPlatform $scriptedResultPlatform): SymfonyAiLLMClient
    {
        return new SymfonyAiLLMClient(new PlatformBinding($scriptedResultPlatform, 'm', new NullLogger()));
    }

    /**
     * @param array<string, mixed> $arguments
     */
    private function callOf(string $toolName, array $arguments): ResultInterface
    {
        return new MultiPartResult([new ToolCallResult([new ToolCall('call-'.$toolName, $toolName, $arguments)])]);
    }
}
