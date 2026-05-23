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
    public function __construct(
        private string $model,
        private ?string $attackerModelOverride,
        private ?string $reviewerModelOverride,
    ) {}

    public function attackerModel(): string
    {
        return $this->attackerModelOverride ?? $this->model;
    }

    public function reviewerModel(): string
    {
        return $this->reviewerModelOverride ?? $this->model;
    }
}
