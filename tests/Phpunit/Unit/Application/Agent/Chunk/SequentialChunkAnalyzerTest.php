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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Chunk;

use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\Validator\Validation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAnalysisRequest;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerContextPromptRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunk\AttackerChunkCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunk\ChunkContextFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunk\SequentialChunkAnalyzer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\RiskMarkerIndex;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\VulnerabilityFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AccessControlMap;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileInventory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullCodeSlicer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullProgressReporter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\NullAttackerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\AttackerPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\RecordingCoverageRecorder;

final class SequentialChunkAnalyzerTest extends TestCase
{
    /**
     * @throws InvalidProjectFileException
     */
    public function test_an_llm_provider_exception_marks_the_chunk_after_the_failing_one_as_errored(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willThrowException(new LLMProviderException('platform gone'));

        $sequentialChunkAnalyzer = new SequentialChunkAnalyzer(
            $llmClient,
            new ChunkContextFactory(new AttackerPromptBuilder(), new NullCodeSlicer(), new AttackerContextPromptRenderer()),
            new AttackerChunkCache(new NullAttackerCache(), $this->vulnerabilityFactory(), new NullLogger()),
            $this->vulnerabilityFactory(),
            new NullLogger(),
            new NullProgressReporter(),
            3,
            false,
            null,
        );

        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        try {
            $sequentialChunkAnalyzer->analyze(
                [[$this->makeFile('src/A.php')], [$this->makeFile('src/B.php')]],
                new AttackerAnalysisRequest([], SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap())),
                $recordingCoverageRecorder,
                null,
                new RiskMarkerIndex([]),
            );
            self::fail('expected LLMProviderException');
        } catch (LLMProviderException) {
            self::assertSame(
                [
                    ['stage' => 'attacker', 'filePath' => 'src/A.php', 'status' => 'errored'],
                    ['stage' => 'attacker', 'filePath' => 'src/B.php', 'status' => 'errored'],
                ],
                $recordingCoverageRecorder->coverage,
            );
        }
    }

    private function vulnerabilityFactory(): VulnerabilityFactory
    {
        return new VulnerabilityFactory(new NullLogger(), Validation::createValidator());
    }

    /**
     * @throws InvalidProjectFileException
     */
    private function makeFile(string $path): ProjectFile
    {
        return ProjectFile::create($path, '/app/'.$path, '<?php');
    }
}
