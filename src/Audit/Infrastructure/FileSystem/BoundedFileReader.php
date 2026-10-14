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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\Exception\UnreadableInputFileException;

/**
 * Reads a file the run takes as input, a baseline or an imported SARIF
 * report, whose path may lead into the audited repository: a `--baseline`
 * in the checkout, a relative `scan.import_sarif` entry. At most
 * {@see self::MAX_BYTES} are read, so a symlink to `/dev/zero` or to a file
 * of the audit host that never ends is refused instead of being read until
 * memory runs out; a pipe the user names (`--baseline=<(…)`) still reads.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class BoundedFileReader
{
    private const int MAX_BYTES = 33_554_432;

    private const int READ_LIMIT = self::MAX_BYTES + 1;

    /**
     * @throws UnreadableInputFileException
     */
    public static function read(string $path): string
    {
        $readError = null;
        set_error_handler(static function (int $severity, string $message) use (&$readError): bool {
            $readError = $message;

            return true;
        });

        try {
            $contents = file_get_contents($path, false, null, 0, self::READ_LIMIT);
        } finally {
            restore_error_handler();
        }

        if (null !== $readError) {
            throw UnreadableInputFileException::forReadError($path, $readError);
        }

        \assert(false !== $contents, 'file_get_contents() raises a warning whenever it fails');

        if (self::READ_LIMIT === \strlen($contents)) {
            throw UnreadableInputFileException::forOversizedFile($path, self::MAX_BYTES);
        }

        return $contents;
    }
}
