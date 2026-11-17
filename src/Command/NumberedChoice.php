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

use Symfony\Component\Console\Question\ChoiceQuestion;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * A question answered by the number of a listed choice, or by typing any
 * other value, which is taken as written.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class NumberedChoice
{
    /**
     * @param list<string>      $choices
     * @param list<string>|null $values  what each choice stands for, when it reads otherwise
     */
    public static function ask(SymfonyStyle $symfonyStyle, string $question, array $choices, string $default, ?array $values = null): string
    {
        $choiceQuestion = new ChoiceQuestion($question, $choices, $default);
        $choiceQuestion->setValidator(static fn (mixed $answer): string => self::chosen($values ?? $choices, \is_string($answer) ? $answer : ''));

        $answer = $symfonyStyle->askQuestion($choiceQuestion);
        \assert(\is_string($answer));

        return $answer;
    }

    /**
     * @param list<string> $choices
     */
    private static function chosen(array $choices, string $answer): string
    {
        return ctype_digit($answer) ? $choices[(int) $answer] ?? $answer : $answer;
    }
}
