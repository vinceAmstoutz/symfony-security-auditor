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

use InvalidArgumentException;

final readonly class RiskMarker
{
    private function __construct(
        private string $filePath,
        private int $line,
        private string $pattern,
        private string $description,
    ) {}

    public static function create(string $filePath, int $line, string $pattern, string $description): self
    {
        if ('' === trim($filePath)) {
            throw new InvalidArgumentException('File path cannot be empty');
        }

        if ($line < 1) {
            throw new InvalidArgumentException('Line number must be >= 1');
        }

        if ('' === trim($pattern)) {
            throw new InvalidArgumentException('Pattern label cannot be empty');
        }

        return new self($filePath, $line, $pattern, $description);
    }

    public function filePath(): string
    {
        return $this->filePath;
    }

    public function line(): int
    {
        return $this->line;
    }

    public function pattern(): string
    {
        return $this->pattern;
    }

    public function description(): string
    {
        return $this->description;
    }
}
