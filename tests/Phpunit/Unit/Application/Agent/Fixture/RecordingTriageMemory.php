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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture;

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\TriageMemoryRecorderInterface;

/**
 * Test fake: keeps the reason of every rejection it is asked to remember in a
 * public buffer, so a test can assert what reached triage memory.
 */
final class RecordingTriageMemory implements TriageMemoryRecorderInterface
{
    /** @var list<string> */
    public array $reasons = [];

    #[Override]
    public function record(string $type, string $file, string $title, int $line, string $reason): void
    {
        $this->reasons[] = $reason;
    }
}
