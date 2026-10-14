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

/**
 * Opt-in companion of {@see SecretScrubberInterface} for a scrubber that also
 * reads the name of the file it scrubs: a file whose name says it holds a
 * secret, such as the decryption key of a Symfony secrets vault, is redacted
 * whatever its content looks like. The scanner checks for it with
 * `instanceof`, so a scrubber without it keeps working through `scrub()`.
 *
 * Implementations must be idempotent: scrubFile($path, scrubFile($path, x)) === scrubFile($path, x).
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
interface PathAwareSecretScrubberInterface extends SecretScrubberInterface
{
    public function scrubFile(string $relativePath, string $content): string;
}
