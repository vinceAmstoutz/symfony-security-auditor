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

final readonly class CweReference
{
    private function __construct(private int $id) {}

    public static function of(int $id): self
    {
        return new self($id);
    }

    public function id(): int
    {
        return $this->id;
    }

    public function label(): string
    {
        return \sprintf('CWE-%d', $this->id);
    }

    public function url(): string
    {
        return \sprintf('https://cwe.mitre.org/data/definitions/%d.html', $this->id);
    }
}
