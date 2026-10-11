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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;

final readonly class CodeLocation
{
    /**
     * @param string|null $echoedFilePath the path as the model wrote it, when `$filePath` names the project file it denotes in another spelling
     *
     * @throws InvalidCodeLocationException
     */
    public function __construct(
        private string $filePath,
        private int $lineStart,
        private int $lineEnd,
        private ?string $echoedFilePath = null,
    ) {
        if ('' === trim($filePath)) {
            throw InvalidCodeLocationException::forBlankFilePath();
        }

        if ($lineStart < 1) {
            throw InvalidCodeLocationException::forNonPositiveLineStart();
        }

        if ($lineEnd < $lineStart) {
            throw InvalidCodeLocationException::forInvalidLineRange();
        }
    }

    public function filePath(): string
    {
        return $this->filePath;
    }

    public function lineStart(): int
    {
        return $this->lineStart;
    }

    public function lineEnd(): int
    {
        return $this->lineEnd;
    }

    /**
     * The path as the model wrote it: {@see self::filePath()} unless the
     * finding was named by another spelling of it.
     *
     * @internal not part of the BC promise — see docs/versioning.md
     */
    public function echoedFilePath(): string
    {
        return $this->echoedFilePath ?? $this->filePath;
    }
}
