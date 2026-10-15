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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception;

use Symfony\AI\Platform\PlatformInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;

/** @internal not part of the BC promise — see docs/versioning.md */
final class MissingAiPlatformException extends LLMProviderException
{
    private static function create(): self
    {
        return new self('No AI platform is configured. Enable a platform (e.g. "anthropic") in config/packages/ai.yaml and set its API key — the symfony/ai-bundle recipe ships with every platform commented out.');
    }

    /**
     * @param list<string> $unselectedPlatforms the platform services configured when none is selected
     */
    public static function forUnselectedPlatforms(array $unselectedPlatforms): self
    {
        if ([] === $unselectedPlatforms) {
            return self::create();
        }

        return new self(\sprintf(
            'Several AI platforms are configured (%1$s) and none is selected: alias %2$s to the one to audit with under "services:" in config/services.yaml, e.g. "%2$s: \'@%3$s\'".',
            implode(', ', $unselectedPlatforms),
            PlatformInterface::class,
            $unselectedPlatforms[0],
        ));
    }
}
