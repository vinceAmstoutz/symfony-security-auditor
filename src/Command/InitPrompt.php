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

use Symfony\Component\Console\Exception\MissingInputException;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * The free-text questions `init` asks: with a default, or required.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class InitPrompt
{
    public static function withDefault(SymfonyStyle $symfonyStyle, string $question, string $default): string
    {
        $answer = $symfonyStyle->ask($question, $default);
        \assert(\is_string($answer));

        return $answer;
    }

    /**
     * Offers no default and returns an empty answer at end of input, on which
     * `QuestionHelper` throws.
     */
    public static function required(SymfonyStyle $symfonyStyle, string $question): string
    {
        try {
            $answer = $symfonyStyle->ask($question);
        } catch (MissingInputException) {
            return '';
        }

        return \is_string($answer) ? $answer : '';
    }
}
