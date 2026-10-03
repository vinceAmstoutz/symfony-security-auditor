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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model;

use DateTimeImmutable;

/**
 * Identity, timing and scope header of an audit report.
 *
 * `filesDiscovered` is what the scan found, `filesScanned` what was actually
 * audited. They differ only for a `--since` run, where the diff narrows the
 * second — so `filesDiscovered === 0` means the scan itself came up empty and
 * no verdict was reached, which is not the same as a diff run finding nothing
 * changed. `costEstimate` marks a `--dry-run`, which analyzes no file.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ReportIdentity
{
    /**
     * @param ?string      $diffSinceRef the git ref a `--since` run diffed against; null for a run over the whole history
     * @param list<string> $scanPaths    the `--path` scopes the scan was restricted to; empty for the whole project
     */
    public function __construct(
        public string $auditId,
        public string $projectPath,
        public DateTimeImmutable $startedAt,
        public DateTimeImmutable $completedAt,
        public int $filesScanned,
        public int $filesDiscovered,
        public bool $costEstimate = false,
        public ?string $diffSinceRef = null,
        public array $scanPaths = [],
    ) {}

    public function durationSeconds(): float
    {
        $elapsed = $this->startedAt->diff($this->completedAt);

        return $elapsed->days * 86_400
            + $elapsed->h * 3_600
            + $elapsed->i * 60
            + $elapsed->s
            + $elapsed->f;
    }
}
