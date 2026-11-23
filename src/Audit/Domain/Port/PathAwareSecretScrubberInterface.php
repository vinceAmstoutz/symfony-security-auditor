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
 * Optional companion of {@see SecretScrubberInterface}, checked with
 * `instanceof`: also reads the file's name, so a file whose name says it holds
 * a secret, such as a Symfony secrets-vault decryption key, is redacted
 * whatever its content.
 *
 * Implementations must be idempotent: scrubFile($path, scrubFile($path, x)) === scrubFile($path, x).
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
interface PathAwareSecretScrubberInterface extends SecretScrubberInterface
{
    public function scrubFile(string $relativePath, string $content): string;
}
