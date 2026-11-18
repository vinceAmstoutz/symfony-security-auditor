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

/**
 * Asks `init` which provider to configure: first how the model is reached,
 * then the providers that serve it that way — or a provider typed directly.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class InitProviderQuestion
{
    public static function ask(SymfonyStyle $symfonyStyle): string
    {
        $answer = NumberedChoice::ask(
            $symfonyStyle,
            'How do you access AI models? Pick a number, or type a provider name',
            array_map(static fn (ModelAccess $modelAccess): string => $modelAccess->label(), ModelAccess::cases()),
            ModelAccess::ApiKey->value,
            array_map(static fn (ModelAccess $modelAccess): string => $modelAccess->value, ModelAccess::cases()),
        );

        $modelAccess = ModelAccess::tryFrom($answer);

        return null === $modelAccess ? $answer : self::askProviderReachedThrough($symfonyStyle, $modelAccess);
    }

    private static function askProviderReachedThrough(SymfonyStyle $symfonyStyle, ModelAccess $modelAccess): string
    {
        $providers = $modelAccess->providers();

        if (1 === \count($providers)) {
            return $providers[0];
        }

        return NumberedChoice::ask($symfonyStyle, $modelAccess->providerQuestion(), array_map(ProviderNames::of(...), $providers), $providers[0], $providers);
    }
}
