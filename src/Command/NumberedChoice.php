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
     * @param string            $default the value an empty answer picks
     */
    public static function ask(SymfonyStyle $symfonyStyle, string $question, array $choices, string $default, ?array $values = null): string
    {
        $values ??= $choices;
        $defaultPosition = array_search($default, $values, true);
        $choiceQuestion = new ChoiceQuestion(
            $question,
            self::numberedFromOne($choices),
            false === $defaultPosition ? $default : (string) ($defaultPosition + 1),
        );
        $choiceQuestion->setValidator(static fn (mixed $answer): string => self::chosen($values, \is_string($answer) ? $answer : ''));

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
     * @param list<string> $choices
     */
    private static function chosen(array $choices, string $answer): string
    {
        return ctype_digit($answer) ? $choices[(int) $answer - 1] ?? $answer : $answer;
    }
}
