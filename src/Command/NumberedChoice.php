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
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class NumberedChoice
{
    /**
     * The prompt names the default by its choice.
     *
     * @param list<string>      $choices
     * @param list<string>|null $values  what each choice stands for, when it reads otherwise
     * @param string            $default the value an empty answer picks
     */
    public static function ask(SymfonyStyle $symfonyStyle, string $question, array $choices, string $default, ?array $values = null): string
    {
        $values ??= $choices;
        $defaultPosition = array_search($default, $values, true);

        return self::askQuestion($symfonyStyle, new ChoiceQuestion($question, self::numberedFromOne($choices), false === $defaultPosition ? $default : (string) ($defaultPosition + 1)), $values);
    }

    /**
     * The prompt names the default by the value it stands for.
     *
     * @param list<string> $choices
     * @param list<string> $values  what each choice stands for
     * @param string       $default the value an empty answer picks
     */
    public static function askNamingTheDefaultValue(SymfonyStyle $symfonyStyle, string $question, array $choices, string $default, array $values): string
    {
        return self::askQuestion($symfonyStyle, new ChoiceQuestion($question, self::numberedFromOne($choices), $default), $values);
    }

    /**
     * @param list<string> $values
     */
    private static function askQuestion(SymfonyStyle $symfonyStyle, ChoiceQuestion $choiceQuestion, array $values): string
    {
        $labels = $choiceQuestion->getChoices();
        $choiceQuestion->setValidator(static fn (mixed $answer): string => self::chosen($values, $labels, \is_string($answer) ? $answer : ''));

        $answer = $symfonyStyle->askQuestion($choiceQuestion);
        \assert(\is_string($answer));

        return $answer;
    }

    /**
     * @param list<string> $choices
     *
     * @return array<int, string>
     */
    private static function numberedFromOne(array $choices): array
    {
        $numbered = [];
        foreach ($choices as $position => $choice) {
            $numbered[$position + 1] = $choice;
        }

        return $numbered;
    }

    /**
     * Maps a number or a label, which a terminal completes a typed value to,
     * to the value it stands for.
     *
     * @param list<string> $values
     * @param array<mixed> $labels the choices, numbered from 1
     */
    private static function chosen(array $values, array $labels, string $answer): string
    {
        $position = ctype_digit($answer) ? (int) $answer : array_search($answer, $labels, true);

        return \is_int($position) ? $values[$position - 1] ?? $answer : $answer;
    }
}
