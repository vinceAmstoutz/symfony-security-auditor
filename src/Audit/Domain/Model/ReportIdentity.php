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
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ReportIdentity
{
    public function __construct(
        public string $auditId,
        public string $projectPath,
        public DateTimeImmutable $startedAt,
        public DateTimeImmutable $completedAt,
        public int $filesScanned,
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
