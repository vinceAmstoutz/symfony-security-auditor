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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\ProviderKey;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\CliAgentPlatforms;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\CliAgentPlatformFactory;

/**
 * The effort a subscription's CLI runs at, asked of a subscription only: no
 * other platform `init` writes takes one.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class InitEffortQuestion
{
    private const string DEFAULT_LEVEL = 'medium';

    public static function ask(SymfonyStyle $symfonyStyle, ProviderKey $providerKey): ?string
    {
        if (!self::takesEffort($providerKey)) {
            return null;
        }

        return NumberedChoice::ask($symfonyStyle, 'Which effort should the model think at? Higher finds more and uses more of the subscription', CliAgentPlatforms::EFFORT_LEVELS, self::DEFAULT_LEVEL);
    }

    public static function takesEffort(ProviderKey $providerKey): bool
    {
        return \array_key_exists($providerKey->platform, CliAgentPlatformFactory::SUBSCRIPTION_MODELS);
    }
}
