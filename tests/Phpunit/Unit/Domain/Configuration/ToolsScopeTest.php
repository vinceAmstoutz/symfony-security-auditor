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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Domain\Configuration;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use ValueError;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Configuration\ToolsScope;

final class ToolsScopeTest extends TestCase
{
    #[DataProvider('configuredScopes')]
    public function test_it_names_the_audited_files_and_the_scanned_files_as_configured(string $configured, ToolsScope $toolsScope): void
    {
        self::assertSame($toolsScope, ToolsScope::from($configured));
        self::assertSame($configured, $toolsScope->value);
    }

    /**
     * @return iterable<string, array{string, ToolsScope}>
     */
    public static function configuredScopes(): iterable
    {
        yield 'the audited files' => ['audited', ToolsScope::Audited];
        yield 'every scanned file' => ['scanned', ToolsScope::Scanned];
    }

    public function test_it_refuses_any_other_scope(): void
    {
        $this->expectException(ValueError::class);

        ToolsScope::from('everything');
    }
}
