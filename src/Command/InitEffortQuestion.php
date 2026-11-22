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

/**
 * The effort the Claude Code CLI runs at, asked of a Claude subscription only:
 * no other platform `init` writes takes one.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class InitEffortQuestion
{
    public const array LEVELS = ['low', 'medium', 'high', 'xhigh', 'max'];

    public const string PLATFORM = 'claudecode';

    private const string DEFAULT_LEVEL = 'medium';

    public static function ask(SymfonyStyle $symfonyStyle, ProviderKey $providerKey): ?string
    {
        if (self::PLATFORM !== $providerKey->platform) {
            return null;
        }

        return NumberedChoice::ask($symfonyStyle, 'Which effort should the model think at? Higher finds more, and uses more of the subscription', self::LEVELS, self::DEFAULT_LEVEL);
    }
}
