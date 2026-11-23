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
 * Renders the product identity banner. One collaborator per entry point owns
 * it: the audit command in a bundle, the application in the standalone
 * binary, whose audit command gets a `NullConsoleBanner`.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
interface ConsoleBannerInterface
{
    public function render(OutputInterface $output): void;
}
