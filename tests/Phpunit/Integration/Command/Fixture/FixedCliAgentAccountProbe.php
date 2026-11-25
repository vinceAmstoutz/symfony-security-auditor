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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Command\Fixture;

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\CliAgentAccount;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\CliAgentAccountProbeInterface;

final readonly class FixedCliAgentAccountProbe implements CliAgentAccountProbeInterface
{
    public function __construct(
        private CliAgentAccount $cliAgentAccount,
    ) {}

    #[Override]
    public function probe(string $agent, ?string $cliBinary): CliAgentAccount
    {
        return $this->cliAgentAccount;
    }
}
