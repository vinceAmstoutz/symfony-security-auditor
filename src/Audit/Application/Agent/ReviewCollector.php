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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent;

/**
 * Accumulates the verdict payloads `RecordReviewTool` records during one
 * review call, until drained.
 *
 * Not readonly: a per-run accumulator (.claude/rules/php-classes.md).
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final class ReviewCollector
{
    /** @var list<array<string, mixed>> */
    private array $payloads = [];

    /**
     * @param array<string, mixed> $payload
     */
    public function add(array $payload): void
    {
        $this->payloads[] = $payload;
    }

    /**
     * @return list<array<string, mixed>>
     */
    public function drain(): array
    {
        $drained = $this->payloads;
        $this->payloads = [];

        return $drained;
    }
}
