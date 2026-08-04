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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Domain\Model;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\FrameworkVocabulary;

final class FrameworkVocabularyTest extends TestCase
{
    public function test_it_defaults_to_naming_symfony(): void
    {
        self::assertSame('Symfony', (new FrameworkVocabulary())->name);
    }

    public function test_it_defaults_to_twig_as_the_template_language(): void
    {
        self::assertSame('Twig', (new FrameworkVocabulary())->templateLanguage);
    }

    public function test_it_defaults_to_the_full_symfony_idiomatic_fix_list(): void
    {
        self::assertSame(
            'parameterized Doctrine query, `#[IsGranted]`, CSRF token, `hash_equals`, an escaping filter, a validator constraint',
            (new FrameworkVocabulary())->idiomaticFixExamples(),
        );
    }

    public function test_it_joins_the_idiomatic_fixes_it_was_given(): void
    {
        $frameworkVocabulary = new FrameworkVocabulary('Laravel', 'Blade', ['an Eloquent binding', '`Gate::authorize`']);

        self::assertSame('an Eloquent binding, `Gate::authorize`', $frameworkVocabulary->idiomaticFixExamples());
    }
}
