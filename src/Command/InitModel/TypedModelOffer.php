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

namespace VinceAmstoutz\SymfonySecurityAuditor\Command\InitModel;

use Override;
use Symfony\Component\Console\Style\SymfonyStyle;
use VinceAmstoutz\SymfonySecurityAuditor\Command\InitPrompt;

/**
 * A model id typed as the provider names it, with a default or without.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class TypedModelOffer implements ModelOfferInterface
{
    public function __construct(
        private string $question,
        private ?string $default = null,
    ) {}

    public static function anyModelId(): self
    {
        return new self('Which model should the <options=bold>auditor</> use? Type its id as your provider names it');
    }

    #[Override]
    public function ask(SymfonyStyle $symfonyStyle, bool $interactive): ?string
    {
        if (null !== $this->default) {
            return InitPrompt::withDefault($symfonyStyle, $this->question, $this->default);
        }

        return $interactive ? InitPrompt::required($symfonyStyle, $this->question) : null;
    }
}
