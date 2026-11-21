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
use Symfony\Component\Console\Output\OutputInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ConnectionTestRunnerInterface;

/**
 * Counts how often `init` ran the connection test, and answers as told.
 */
final class RecordingConnectionTestRunner implements ConnectionTestRunnerInterface
{
    public int $runs = 0;

    public function __construct(private readonly bool $succeeds = true) {}

    #[Override]
    public function run(OutputInterface $output): bool
    {
        ++$this->runs;

        return $this->succeeds;
    }
}
