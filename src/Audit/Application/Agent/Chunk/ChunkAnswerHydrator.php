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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunk;

use JsonException;
use Psr\Log\LoggerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\KnownFiles;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\VulnerabilityFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityHydrationResult;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\CoverageRecorderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMAnswerJsonDecoder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;

/**
 * Turns the model's answer on a chunk into its findings and coverage, from
 * the JSON answer or from the payloads a structured turn recorded.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class ChunkAnswerHydrator
{
    private const int PARSE_FAILURE_PREVIEW_BYTES = 512;

    private ChunkOutcomeRecorder $chunkOutcomeRecorder;

    public function __construct(
        AttackerChunkCache $attackerChunkCache,
        private VulnerabilityFactory $vulnerabilityFactory,
        private LoggerInterface $logger,
    ) {
        $this->chunkOutcomeRecorder = new ChunkOutcomeRecorder($attackerChunkCache, $logger);
    }

    /**
     * @param list<ProjectFile> $chunk
     */
    public function hydrateJsonAnswer(array $chunk, LLMResponse $llmResponse, ChunkContext $chunkContext, CoverageRecorderInterface $coverageRecorder): VulnerabilityHydrationResult
    {
        if ($llmResponse->isDegraded()) {
            return $this->hydrateIncompleteAnswer($chunk, $llmResponse, $this->parseablePayload($llmResponse), $coverageRecorder, $chunkContext->knownFiles);
        }

        $chunkContext = $chunkContext->answeredBy($llmResponse);
        if ($llmResponse->isEmpty()) {
            return $this->settle($chunk, $chunkContext, [], $coverageRecorder);
        }

        try {
            /** @var list<array<string, mixed>> $rawData */
            $rawData = $this->findingsIn($llmResponse->parseJson(), $llmResponse->content());
        } catch (JsonException $jsonException) {
            $this->logger->error('Failed to parse attacker agent JSON response', [
                'error' => $jsonException->getMessage(),
                'content_preview' => substr($llmResponse->content(), 0, self::PARSE_FAILURE_PREVIEW_BYTES),
            ]);
            ChunkCoverageRecorder::recordErrored($chunk, ChunkFailureReason::NOT_JSON, $coverageRecorder);

            return VulnerabilityHydrationResult::empty();
        }

        return $this->settle($chunk, $chunkContext, $rawData, $coverageRecorder);
    }

    /**
     * @param list<ProjectFile>          $chunk
     * @param list<array<string, mixed>> $rawData
     */
    public function settle(array $chunk, ChunkContext $chunkContext, array $rawData, CoverageRecorderInterface $coverageRecorder): VulnerabilityHydrationResult
    {
        $vulnerabilityHydrationResult = $this->vulnerabilityFactory->fromList($rawData, $chunkContext->knownFiles);
        $this->chunkOutcomeRecorder->record($chunk, $chunkContext, $rawData, $vulnerabilityHydrationResult, $coverageRecorder);

        return $vulnerabilityHydrationResult;
    }

    /**
     * Records a degraded answer as errored and uncached, keeping its findings,
     * so the next run retries the chunk.
     *
     * @param list<ProjectFile> $chunk
     * @param list<mixed>       $rawData
     * @param KnownFiles        $knownFiles the files its findings are named by
     */
    public function hydrateIncompleteAnswer(array $chunk, LLMResponse $llmResponse, array $rawData, CoverageRecorderInterface $coverageRecorder, KnownFiles $knownFiles): VulnerabilityHydrationResult
    {
        $this->logger->warning('Attacker response was cut short; the chunk is recorded as errored and left out of the cache', [
            'stop_reason' => $llmResponse->stopReason(),
            'files' => array_map(static fn (ProjectFile $projectFile): string => $projectFile->relativePath(), $chunk),
            'findings_kept' => \count($rawData),
        ]);
        ChunkCoverageRecorder::recordErrored($chunk, ChunkFailureReason::fromStopReason($llmResponse->stopReason()), $coverageRecorder);

        return $this->vulnerabilityFactory->fromList($rawData, $knownFiles);
    }

    /**
     * Returns the findings a cut-short JSON answer still carries, as a list
     * even when `parseJson()` recovers a lone finding object.
     *
     * @return list<mixed>
     */
    private function parseablePayload(LLMResponse $llmResponse): array
    {
        try {
            $decoded = $llmResponse->parseJson();
        } catch (JsonException) {
            return [];
        }

        return array_is_list($decoded) ? $decoded : [$decoded];
    }

    /**
     * Reads an object that is the answer's only JSON as a lone finding and any
     * other object as its values, so a finding it leaves out keeps the chunk
     * unanalyzed and uncached.
     *
     * @param array<array-key, mixed> $decoded
     *
     * @return list<mixed>
     */
    private function findingsIn(array $decoded, string $answer): array
    {
        return $this->isLoneFinding($decoded, $answer) ? [$decoded] : array_values($decoded);
    }

    /**
     * @param array<array-key, mixed> $decoded
     */
    private function isLoneFinding(array $decoded, string $answer): bool
    {
        return !array_is_list($decoded)
            && [] !== array_filter($decoded, static fn (mixed $value): bool => !\is_array($value))
            && LLMAnswerJsonDecoder::holdsOneValue($answer);
    }
}
