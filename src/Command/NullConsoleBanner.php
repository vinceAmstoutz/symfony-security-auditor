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

/**
 * Prints nothing. Wired in the standalone binary, where
 * `StandaloneApplication` already renders the banner for every command
 * before the audit command is even resolved.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class NullConsoleBanner implements ConsoleBannerInterface
{
    #[Override]
    public function render(OutputInterface $output): void
    {
        // no-op
    }
}
