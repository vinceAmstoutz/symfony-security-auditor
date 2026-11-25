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
 * The model `init --no-interaction` writes for a provider it cannot list
 * models for, marked in the written configuration and announced.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class PlaceholderModel
{
    public const string MODEL = 'claude-opus-5-5';

    public const string COMMENT = 'A placeholder: replace it with a model the provider serves.';

    /**
     * @param ?string $chosenModel the model given or chosen, null where none could be
     */
    public static function or(?string $chosenModel): string
    {
        return $chosenModel ?? self::MODEL;
    }

    /**
     * @return array<string, string> the comment to write above each key of the configuration
     */
    public static function comments(?string $chosenModel): array
    {
        return null === $chosenModel ? ['model' => self::COMMENT] : [];
    }

    public static function announce(SymfonyStyle $symfonyStyle, ?string $chosenModel): void
    {
        if (null === $chosenModel) {
            $symfonyStyle->warning(\sprintf('init cannot list the models of this provider, so it writes %s as a placeholder. Set model: in the written configuration to a model the provider serves, or run init again with --model.', self::MODEL));
        }
    }
}
