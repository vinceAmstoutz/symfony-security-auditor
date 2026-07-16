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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port;

use Override;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class NullTriageMemoryRecorder implements TriageMemoryRecorderInterface
{
    #[Override]
    public function record(string $type, string $file, string $title, string $reason): void {}
}
