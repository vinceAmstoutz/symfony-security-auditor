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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Delay;

/**
 * Synchronous-sleep adapter. Injected so retry tests stay deterministic
 * (FakeSleeper records durations and returns immediately).
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
interface SleeperInterface
{
    public function sleep(int $milliseconds): void;
}
