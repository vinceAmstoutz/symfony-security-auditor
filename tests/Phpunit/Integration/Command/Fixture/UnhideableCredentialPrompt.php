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
use RuntimeException;
use Symfony\Component\Console\Style\SymfonyStyle;
use VinceAmstoutz\SymfonySecurityAuditor\Command\CredentialPromptInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\HiddenInputUnavailableException;

/**
 * Stands in for a terminal that cannot hide what is typed into it.
 */
final readonly class UnhideableCredentialPrompt implements CredentialPromptInterface
{
    #[Override]
    public function ask(SymfonyStyle $symfonyStyle, string $question): ?string
    {
        throw HiddenInputUnavailableException::create(new RuntimeException('Unable to hide the response.'));
    }
}
