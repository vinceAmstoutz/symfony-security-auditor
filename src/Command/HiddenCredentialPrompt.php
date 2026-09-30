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
 * Console's hidden question falls back to echoing when it cannot hide the
 * input — a terminal without `stty` — which would print the key under a
 * prompt promising the opposite, so that fallback is off and the situation
 * is reported instead. A pasted key routinely carries the newline or the
 * stray space that came with it, and the provider rejects those without
 * saying why, so the answer is trimmed.
 *
 * @internal not part of the BC promise — see docs/versioning.md
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
