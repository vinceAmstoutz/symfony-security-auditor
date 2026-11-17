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
    private const string SUBSCRIPTION_NOTE = 'A chat subscription is not an API key: Anthropic does not let other tools use Claude plans, and ChatGPT, Gemini and Copilot plans do not include API access either. Create an API key instead — Anthropic: https://console.anthropic.com/settings/keys, OpenAI: https://platform.openai.com/api-keys, Google: https://aistudio.google.com/apikey, Mistral: https://console.mistral.ai/api-keys — then pick its provider below.';

    public static function ask(SymfonyStyle $symfonyStyle): string
    {
        $answer = NumberedChoice::ask(
            $symfonyStyle,
            'How do you reach an AI model? Pick a number, or type a provider name if you know it',
            array_map(static fn (ModelAccess $modelAccess): string => $modelAccess->label(), ModelAccess::cases()),
            '0',
            array_map(static fn (ModelAccess $modelAccess): string => $modelAccess->value, ModelAccess::cases()),
        );

        $modelAccess = ModelAccess::tryFrom($answer);

        return null === $modelAccess ? $answer : self::askProviderReachedThrough($symfonyStyle, $modelAccess);
    }

    private static function askProviderReachedThrough(SymfonyStyle $symfonyStyle, ModelAccess $modelAccess): string
    {
        if (ModelAccess::Subscription === $modelAccess) {
            $symfonyStyle->note(self::SUBSCRIPTION_NOTE);
        }

        $providers = $modelAccess->providers();

        return 1 === \count($providers)
            ? $providers[0]
            : NumberedChoice::ask($symfonyStyle, 'Which AI provider do you want to use? Pick a number, or type any symfony/ai platform — e.g. ollama, or generic.my_gateway for an AI gateway', $providers, '0');
    }
}
