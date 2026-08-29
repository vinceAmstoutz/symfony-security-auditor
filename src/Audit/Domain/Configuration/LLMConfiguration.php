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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Configuration;

final readonly class LLMConfiguration
{
    public const string DEFAULT_MODEL = 'claude-opus-5';

    public const int DEFAULT_MAX_OUTPUT_TOKENS = 8192;

    public function __construct(
        private string $model,
        private ?string $attackerModelOverride,
        private ?string $reviewerModelOverride,
        private int $maxOutputTokens = self::DEFAULT_MAX_OUTPUT_TOKENS,
        private ?int $attackerMaxOutputTokensOverride = null,
        private ?int $reviewerMaxOutputTokensOverride = null,
        public bool $providerJsonMode = false,
    ) {}

    public function attackerModel(): string
    {
        return $this->attackerModelOverride ?? $this->model;
    }

    public function reviewerModel(): string
    {
        return $this->reviewerModelOverride ?? $this->model;
    }

    public function attackerMaxOutputTokens(): int
    {
        return $this->attackerMaxOutputTokensOverride ?? $this->maxOutputTokens;
    }

    public function reviewerMaxOutputTokens(): int
    {
        return $this->reviewerMaxOutputTokensOverride ?? $this->maxOutputTokens;
    }
}
