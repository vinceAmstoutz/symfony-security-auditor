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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Bundle\Fixture;

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\TokenEstimator\ProviderTokenEstimatorInterface;

use function Symfony\Component\String\u;

final class AcmeTokenEstimator implements ProviderTokenEstimatorInterface
{
    public const int ESTIMATE = 42;

    #[Override]
    public function supports(string $model): bool
    {
        return u($model)->startsWith('acme-');
    }

    #[Override]
    public function estimateTokens(string $text, string $model): int
    {
        return self::ESTIMATE;
    }
}
