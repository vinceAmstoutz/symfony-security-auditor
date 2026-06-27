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
     * @throws InvalidCodeLocationException
     */
    public function __construct(
        private string $filePath,
        private int $lineStart,
        private int $lineEnd,
    ) {
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
}
