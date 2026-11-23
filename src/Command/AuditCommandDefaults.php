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
 * The `audit.min_score`, `audit.fail_on_incomplete`, `audit.format` and
 * `audit.output` settings. The matching flag always wins over them.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class AuditCommandDefaults
{
    public function __construct(
        public ?int $minScore = null,
        public bool $failOnIncomplete = false,
        public OutputFormat $format = OutputFormat::Console,
        public ?string $output = null,
    ) {}
}
