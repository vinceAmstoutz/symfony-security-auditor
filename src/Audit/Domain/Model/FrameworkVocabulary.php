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
 * The framework wording the synthesizer prompts need: the framework's name, the
 * name of its template language, and the idiomatic remediations a fix should
 * prefer over a hand-rolled guard. Both synthesizers are otherwise portable, so
 * injecting this is what keeps them from naming Symfony in a prompt literal.
 * The defaults describe Symfony, which is what this package audits.
 *
 * @internal not part of the BC promise — see docs/versioning.md
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
