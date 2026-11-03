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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM;

/**
 * Whether the platform of one client still streams its answers: once a
 * stream ended without reporting its usage, the bill of a streamed answer is
 * unknown, so that client calls the platform without streaming for the rest
 * of the run.
 *
 * Not `readonly` because it remembers that verdict; see
 * `.claude/rules/php-classes.md` (stateful collaborator carve-out).
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final class StreamMetering
{
    private bool $metered = true;

    public function isMetered(): bool
    {
        return $this->metered;
    }

    public function stopStreaming(): void
    {
        $this->metered = false;
    }
}
