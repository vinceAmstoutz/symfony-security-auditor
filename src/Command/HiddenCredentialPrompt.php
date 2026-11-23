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
use Symfony\Component\Console\Exception\MissingInputException;
use Symfony\Component\Console\Exception\RuntimeException;
use Symfony\Component\Console\Question\Question;
use Symfony\Component\Console\Style\SymfonyStyle;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\HiddenInputUnavailableException;

use function Symfony\Component\String\b;

/**
 * Never echoes the key: Console's echo fallback for a terminal that cannot
 * hide input (no `stty`) is off, so that case throws.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class HiddenCredentialPrompt implements CredentialPromptInterface
{
    /**
     * @throws HiddenInputUnavailableException
     */
    #[Override]
    public function ask(SymfonyStyle $symfonyStyle, string $question): ?string
    {
        try {
            $answer = $symfonyStyle->askQuestion((new Question($question))->setHidden(true)->setHiddenFallback(false));
        } catch (MissingInputException) {
            return null;
        } catch (RuntimeException $runtimeException) {
            throw HiddenInputUnavailableException::create($runtimeException);
        }

        $credential = b(\is_string($answer) ? $answer : '')->trim()->toString();

        return '' !== $credential ? $credential : null;
    }
}
