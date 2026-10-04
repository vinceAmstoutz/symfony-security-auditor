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
use Symfony\Component\Console\Style\SymfonyStyle;
use VinceAmstoutz\SymfonySecurityAuditor\Command\CredentialPromptInterface;

/**
 * Answers every prompt with the same credential and counts how often it was asked.
 */
final class RecordingCredentialPrompt implements CredentialPromptInterface
{
    public int $asked = 0;

    public function __construct(private readonly string $credential) {}

    /**
     * @throws void
     */
    #[Override]
    public function ask(SymfonyStyle $symfonyStyle, string $question): string
    {
        ++$this->asked;

        return $this->credential;
    }
}
