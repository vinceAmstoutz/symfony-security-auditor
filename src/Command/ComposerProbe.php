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

namespace VinceAmstoutz\SymfonySecurityAuditor\Command;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class ComposerProbe
{
    private function __construct(
        public bool $isAvailable,
        public string $failure,
    ) {}

    public static function available(): self
    {
        return new self(true, '');
    }

    /**
     * @param string $failure what the probe reported, already safe to print to a terminal
     */
    public static function unavailable(string $failure): self
    {
        return new self(false, $failure);
    }
}
