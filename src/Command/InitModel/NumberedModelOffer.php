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
use VinceAmstoutz\SymfonySecurityAuditor\Command\NumberedChoice;

/**
 * A list of models picked by number, or any other model id typed.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class NumberedModelOffer implements ModelOfferInterface
{
    /**
     * @param non-empty-list<string> $choices
     * @param non-empty-list<string> $values  what each choice stands for
     */
    public function __construct(
        private string $question,
        private array $choices,
        private array $values,
        private string $default,
        private ?string $preamble = null,
    ) {}

    /**
     * @param non-empty-list<string> $models
     */
    public static function of(string $question, array $models, string $default): self
    {
        return new self($question, $models, $models, $default);
    }

    #[Override]
    public function ask(SymfonyStyle $symfonyStyle, bool $interactive): string
    {
        if (null !== $this->preamble) {
            $symfonyStyle->text($this->preamble);
        }

        return NumberedChoice::askNamingTheDefaultValue($symfonyStyle, $this->question, $this->choices, $this->default, $this->values);
    }
}
