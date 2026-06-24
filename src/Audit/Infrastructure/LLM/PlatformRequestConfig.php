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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\TokenEstimatorInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\TokenEstimator\ResolvingTokenEstimator;

/**
 * How each request body is shaped: sampling temperature, provider JSON mode,
 * and the token estimator used for rate-limit accounting.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class PlatformRequestConfig
{
    public function __construct(
        public ?float $temperature = SymfonyAiLLMClient::DEFAULT_TEMPERATURE,
        public bool $providerJsonMode = SymfonyAiLLMClient::DEFAULT_PROVIDER_JSON_MODE,
        public TokenEstimatorInterface $tokenEstimator = new ResolvingTokenEstimator(),
    ) {}
}
