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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture;

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\TokenEstimatorInterface;

final class FixedTokenEstimator implements TokenEstimatorInterface
{
    public function __construct(private readonly int $tokensPerCall) {}

    #[Override]
    public function estimateTokens(string $text, string $model): int
    {
        return $this->tokensPerCall;
    }
}
