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
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\RunRefusedException;

/** @internal not part of the BC promise, see docs/versioning.md */
interface UnpricedModelBudgetGuardInterface
{
    /**
     * Warns when a configured model has no published price. With a cost budget
     * set, which then cannot be enforced, it asks for confirmation and returns
     * false under `--no-interaction`.
     *
     * @throws RunRefusedException when the run must not start for another reason than the budget
     */
    public function permitsRun(InputInterface $input, SymfonyStyle $symfonyStyle): bool;

    /**
     * For an entry point with nobody to confirm, such as the MCP server: logs
     * that the cost budget cannot be enforced on an unpriced model and refuses
     * a run that `permitsRun()` refuses without asking.
     *
     * @throws RunRefusedException
     */
    public function assertUnattendedRunPermitted(LoggerInterface $logger): void;
}
