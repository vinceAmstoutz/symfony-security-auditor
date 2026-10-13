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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SkippedFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SkippedFileReason;

/**
 * A file whose content mixes bytes that are not valid UTF-8 with the
 * characters {@see Utf8Normalizer} repairs them into could read two different
 * names as one once repaired, so the scan leaves it out.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class AmbiguousContent
{
    public static function skipped(string $relativePath, string $content): ?SkippedFile
    {
        return Utf8Normalizer::isAmbiguous($content) ? new SkippedFile($relativePath, SkippedFileReason::AmbiguousContent) : null;
    }
}
