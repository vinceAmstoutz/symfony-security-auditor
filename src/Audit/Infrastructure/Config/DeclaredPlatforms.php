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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\ProviderKey;

/**
 * The platforms the bundled `symfony/ai-bundle` declares under `ai.platform`,
 * as its `config/options.php` imports them. A configuration naming any other
 * stops the container outright (`Unrecognized option "meta" under
 * "ai.platform"`), so `init` writes nothing for it and installs no bridge.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class DeclaredPlatforms
{
    /**
     * @var list<string>
     */
    public const array NAMES = [
        'albert', 'amazeeai', 'anthropic', 'azure', 'bedrock', 'cache', 'cartesia', 'cerebras', 'cohere', 'decart',
        'deepgram', 'deepseek', 'dockermodelrunner', 'edenai', 'elevenlabs', 'failover', 'fireworks', 'gemini', 'generic',
        'higgsfield', 'huggingface', 'lmstudio', 'minimax', 'mistral', 'ollama', 'openai', 'openresponses', 'openrouter',
        'ovh', 'perplexity', 'scaleway', 'together', 'transformersphp', 'typesafe', 'venice', 'vertexai', 'voyage',
    ];

    public static function declares(ProviderKey $providerKey): bool
    {
        return \in_array($providerKey->platform, self::NAMES, true);
    }

    /**
     * Every platform `init` takes on — the ones wrapping others it refuses
     * outright — spelled the way a provider naming it must be, so a reader
     * picking one is not refused again for leaving out the instance.
     *
     * @return list<string>
     */
    public static function initShapes(): array
    {
        $shapes = [];

        foreach (array_diff(self::NAMES, array_keys(CompoundPlatforms::SERVICES_NEEDED)) as $platform) {
            $shapes[] = \in_array($platform, InstanceKeyedPlatforms::NAMES, true) ? \sprintf('%s.<instance>', $platform) : $platform;
        }

        return $shapes;
    }
}
