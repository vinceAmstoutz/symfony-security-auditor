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
 * Removes credential-shaped strings from file contents before they reach the LLM.
 *
 * Implementations must be idempotent: scrub(scrub(x)) === scrub(x).
 */
interface SecretScrubberInterface
{
    public function scrub(string $content): string;
}
