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

use Override;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Output\StreamOutput;

/**
 * The output `audit:run` prints to, set by the command before it writes a
 * report. No output set is no terminal.
 *
 * Not readonly: the output is set after construction. A late-bound holder
 * per .claude/rules/php-classes.md.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final class CommandOutputHolder implements StandardOutputInterface
{
    private ?OutputInterface $output = null;

    public function set(OutputInterface $output): void
    {
        $this->output = $output;
    }

    #[Override]
    public function isTerminal(): bool
    {
        return $this->output instanceof StreamOutput && stream_isatty($this->output->getStream());
    }
}
