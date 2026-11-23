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
use Symfony\Component\Console\Formatter\OutputFormatter;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Names the API key the run spends, in the standalone binary's audit header,
 * by its masked preview only.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class CredentialConsoleBanner implements ConsoleBannerInterface
{
    public function __construct(private string $maskedCredential) {}

    #[Override]
    public function render(OutputInterface $output): void
    {
        $output->writeln(\sprintf('API key: <info>%s</info>', OutputFormatter::escape($this->maskedCredential)));
    }
}
