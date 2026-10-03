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

use Symfony\Component\Console\Style\SymfonyStyle;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\HiddenInputUnavailableException;

/**
 * Asks the user for a credential on the console without ever echoing it.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
interface CredentialPromptInterface
{
    /**
     * @return string|null the trimmed credential, or null when nothing usable was entered
     *
     * @throws HiddenInputUnavailableException when the terminal cannot hide what is typed
     */
    public function ask(SymfonyStyle $symfonyStyle, string $question): ?string;
}
