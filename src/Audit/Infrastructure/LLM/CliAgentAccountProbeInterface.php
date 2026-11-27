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
 * Asks a coding agent's CLI which account its calls bill.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
interface CliAgentAccountProbeInterface
{
    /**
     * @param string  $agent     `claudecode` or `codex`
     * @param ?string $cliBinary the CLI the configuration names, else the one on the `PATH`
     */
    public function probe(string $agent, ?string $cliBinary): CliAgentAccount;
}
