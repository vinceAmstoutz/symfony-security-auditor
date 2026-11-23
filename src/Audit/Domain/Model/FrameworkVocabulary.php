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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model;

/**
 * The framework wording of the synthesizer prompts: the framework's name, its
 * template language and the idiomatic fixes to prefer over a hand-rolled guard.
 * Defaults to Symfony.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class FrameworkVocabulary
{
    /**
     * @param list<string> $idiomaticFixes
     */
    public function __construct(
        public string $name = 'Symfony',
        public string $templateLanguage = 'Twig',
        public array $idiomaticFixes = [
            'parameterized Doctrine query',
            '`#[IsGranted]`',
            'CSRF token',
            '`hash_equals`',
            'an escaping filter',
            'a validator constraint',
        ],
    ) {}

    public function idiomaticFixExamples(): string
    {
        return implode(', ', $this->idiomaticFixes);
    }
}
