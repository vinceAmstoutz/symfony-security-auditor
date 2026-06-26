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

use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

/** @internal not part of the BC promise — see docs/versioning.md */
interface UnpricedModelBudgetGuardInterface
{
    /**
     * Warns when a configured model has no published price (cost reporting will
     * read `$0.00` for it). When a cost budget is also set the guard cannot
     * enforce it, so it prompts interactively and returns `false` (fail closed)
     * under `--no-interaction`. Returns `true` to let the run proceed.
     */
    public function permitsRun(InputInterface $input, SymfonyStyle $symfonyStyle): bool;
}
