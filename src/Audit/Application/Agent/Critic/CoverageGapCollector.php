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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Critic;

/**
 * Accumulates the raw gap payloads `record_coverage_gap` captures during the
 * coverage critic's one conversation. Mutable by design — opted out of the
 * final readonly rule as a per-run accumulator (see
 * .claude/rules/php-classes.md).
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final class CoverageGapCollector
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
