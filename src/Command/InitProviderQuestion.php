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
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\MissingChoiceException;

/**
 * Asks `init` which provider to configure: first how the model is reached,
 * then the providers that serve it that way, or a provider typed directly.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class InitProviderQuestion
{
    private const int ATTEMPTS_AWAY_FROM_A_TERMINAL = 3;

    /**
     * Returns the provider `init --no-interaction` configures, after saying
     * so and turning interaction off, when the input ends before an answer
     * or, away from a terminal, keeps answering nothing.
     */
    public static function ask(SymfonyStyle $symfonyStyle, InputInterface $input, bool $atATerminal): string
    {
        if (!$input->isInteractive()) {
            return self::unasked();
        }

        try {
            return self::answered($symfonyStyle, $atATerminal ? null : self::ATTEMPTS_AWAY_FROM_A_TERMINAL);
        } catch (MissingInputException|MissingChoiceException) {
            $input->setInteractive(false);
            $symfonyStyle->text('No answer was given: init continues as with --no-interaction.');

            return self::unasked();
        }
    }

    private static function unasked(): string
    {
        return ModelAccess::ApiKey->providers()[0];
    }

    /**
     * @throws MissingChoiceException
     * @throws MissingInputException
     */
    private static function answered(SymfonyStyle $symfonyStyle, ?int $maxAttempts): string
    {
        $answer = NumberedChoice::askWithoutDefault(
            $symfonyStyle,
            'How do you access AI models? Pick a number, or type a provider name',
            array_map(static fn (ModelAccess $modelAccess): string => $modelAccess->label(), ModelAccess::cases()),
            array_map(static fn (ModelAccess $modelAccess): string => $modelAccess->value, ModelAccess::cases()),
            $maxAttempts,
        );

        $modelAccess = ModelAccess::tryFrom($answer);

        return null === $modelAccess ? $answer : self::askProviderReachedThrough($symfonyStyle, $modelAccess, $maxAttempts);
    }

    /**
     * @throws MissingChoiceException
     * @throws MissingInputException
     */
    private static function askProviderReachedThrough(SymfonyStyle $symfonyStyle, ModelAccess $modelAccess, ?int $maxAttempts): string
    {
        $providers = $modelAccess->providers();

        if (1 === \count($providers)) {
            return $providers[0];
        }

        return NumberedChoice::askWithoutDefault($symfonyStyle, $modelAccess->providerQuestion(), array_map(ProviderNames::of(...), $providers), $providers, $maxAttempts);
    }
}
