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

use Symfony\Component\Console\Output\OutputInterface;

/**
 * Runs `doctor --check-connection` for `init`, in a process of its own so
 * the provider bridge `init` just installed is the one loaded.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
interface ConnectionTestRunnerInterface
{
    /**
     * @return bool whether the provider answered
     */
    public function run(OutputInterface $output): bool;
}
