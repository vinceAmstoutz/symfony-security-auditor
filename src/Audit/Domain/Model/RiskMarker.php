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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidRiskMarkerException;

final readonly class RiskMarker
{
    private function __construct(
        private string $filePath,
        private int $line,
        private string $pattern,
        private string $description,
    ) {}

    /**
     * @throws InvalidRiskMarkerException
     */
    public static function create(string $filePath, int $line, string $pattern, string $description): self
    {
        if ('' === trim($filePath)) {
            throw InvalidRiskMarkerException::forBlankFilePath();
        }

        if ($line < 1) {
            throw InvalidRiskMarkerException::forNonPositiveLine();
        }

        if ('' === trim($pattern)) {
            throw InvalidRiskMarkerException::forBlankPattern();
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
