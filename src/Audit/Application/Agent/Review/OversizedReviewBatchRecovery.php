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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review;

use Closure;
use Psr\Log\LoggerInterface;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolRegistryException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\CoverageRecorderInterface;

/**
 * Splits a review batch the model could not take in whole into halves that go
 * back through the analyzer's batch path. Records a single finding that does
 * not fit with its file as errored.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class OversizedReviewBatchRecovery
{
    public function __construct(
        private BatchVerdictApplier $batchVerdictApplier,
        private LoggerInterface $logger,
    ) {}

    /**
     * @param list<Vulnerability>                               $batch
     * @param Closure(list<Vulnerability>): list<Vulnerability> $reviewBatch
     *
     * @return list<Vulnerability>
     *
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function recover(array $batch, Throwable $throwable, CoverageRecorderInterface $coverageRecorder, Closure $reviewBatch): array
    {
        if (1 === \count($batch)) {
            return $this->batchVerdictApplier->recordBatchError($batch, $throwable, $coverageRecorder);
        }

        $this->logger->warning('Reviewer batch exceeds the model input limit; it is split in two and each half reviewed on its own', [
            'batch_size' => \count($batch),
            'error' => $throwable->getMessage(),
        ]);

        $firstHalfSize = intdiv(\count($batch) + 1, 2);
        $secondHalf = \array_slice($batch, $firstHalfSize);

        return [
            ...$this->reviewFirstHalf(\array_slice($batch, 0, $firstHalfSize), $secondHalf, $coverageRecorder, $reviewBatch),
            ...$reviewBatch($secondHalf),
        ];
    }

    /**
     * Gives the second half a status of its own when an abort stops the first.
     *
     * @param list<Vulnerability>                               $firstHalf
     * @param list<Vulnerability>                               $secondHalf
     * @param Closure(list<Vulnerability>): list<Vulnerability> $reviewBatch
     *
     * @return list<Vulnerability>
     *
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    private function reviewFirstHalf(array $firstHalf, array $secondHalf, CoverageRecorderInterface $coverageRecorder, Closure $reviewBatch): array
    {
        try {
            return $reviewBatch($firstHalf);
        } catch (BudgetExceededException $budgetExceededException) {
            $this->batchVerdictApplier->markBatchUnreached($secondHalf, 'aborted', $coverageRecorder);

            throw $budgetExceededException;
        } catch (LLMProviderException $llmProviderException) {
            $this->batchVerdictApplier->markBatchUnreached($secondHalf, 'errored', $coverageRecorder);

            throw $llmProviderException;
        }
    }
}
