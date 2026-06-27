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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem;

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\SecretScrubberInterface;

/**
 * Passthrough implementation used when secret scrubbing is disabled.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class NullSecretScrubber implements SecretScrubberInterface
{
    #[Override]
    public function scrub(string $content): string
    {
        return $content;
    }
}
