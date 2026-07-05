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

namespace VinceAmstoutz\SymfonySecurityAuditor\Command;

/**
 * A single finding surfaced by {@see ReportDifferInterface}, carrying only the
 * fields a diff needs to identify and display it.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class DiffFinding
{
    public function __construct(
        public string $fingerprint,
        public string $type,
        public string $file,
        public string $title,
        public string $severity,
    ) {}

    /**
     * @return array{fingerprint: string, type: string, file: string, title: string, severity: string}
     */
    public function toArray(): array
    {
        return [
            'fingerprint' => $this->fingerprint,
            'type' => $this->type,
            'file' => $this->file,
            'title' => $this->title,
            'severity' => $this->severity,
        ];
    }
}
