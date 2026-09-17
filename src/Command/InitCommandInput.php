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

use Symfony\Component\Console\Attribute\Option;

/**
 * Symfony Console MapInput reflects class properties and requires public mutable fields
 * with property-level defaults; promoted readonly ctor params are invisible to its reflection.
 * Treated as a context carrier per .claude/rules/php-classes.md.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final class InitCommandInput
{
    #[Option(description: 'AI provider to configure (any symfony/ai platform — e.g. anthropic, openai, gemini); defaults to anthropic. Instance-keyed platforms take the instance too, e.g. generic.my_gateway. Skips the prompt when set.')]
    public ?string $provider = null;

    #[Option(description: 'Model the auditor should use; defaults to claude-opus-4-8 for every provider, so set it for any other. Skips the prompt when set.')]
    public ?string $model = null;

    #[Option(description: 'Environment variable holding the API key; defaults to <PLATFORM>_API_KEY')]
    public ?string $envVar = null;

    #[Option(description: 'Base URL of the platform endpoint, required by the platforms that declare one (albert, amazeeai, generic.<instance>, openresponses.<instance>); passing it with any other platform is rejected. Skips the prompt when set.')]
    public ?string $baseUrl = null;

    #[Option(description: 'Overwrite an existing configuration without asking')]
    public bool $force = false;
}
