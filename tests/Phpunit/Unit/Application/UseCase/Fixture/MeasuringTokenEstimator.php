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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\UseCase\Fixture;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\TokenEstimatorInterface;

/**
 * Recording estimator — returns 0 but captures the length of the last input seen.
 *
 * @internal scoped to EstimateAuditCostUseCaseTest
 */
final class MeasuringTokenEstimator implements TokenEstimatorInterface
{
    public int $lastInputLength = -1;

    public function estimateTokens(string $text, string $model): int
    {
        $this->lastInputLength = mb_strlen($text);

        return 0;
    }
}
