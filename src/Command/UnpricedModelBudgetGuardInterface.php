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

use Psr\Log\LoggerInterface;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

/** @internal not part of the BC promise, see docs/versioning.md */
interface UnpricedModelBudgetGuardInterface
{
    /**
     * Warns when a configured model has no published price. With a cost budget
     * set, which then cannot be enforced, it asks for confirmation and returns
     * false under `--no-interaction`.
     */
    public function permitsRun(InputInterface $input, SymfonyStyle $symfonyStyle): bool;

    /**
     * Logs that the cost budget cannot be enforced on an unpriced model, for
     * an entry point with nobody to confirm, such as the MCP server.
     */
    public function warnWhenBudgetCannotBeEnforced(LoggerInterface $logger): void;
}
