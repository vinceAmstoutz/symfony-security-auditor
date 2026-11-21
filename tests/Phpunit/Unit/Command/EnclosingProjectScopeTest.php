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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Command;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Command\EnclosingProjectScope;

final class EnclosingProjectScopeTest extends TestCase
{
    public function test_it_lists_every_path_the_run_is_narrowed_to(): void
    {
        self::assertSame(
            'Scope: <info>src/Controller, src/Entity</info> <fg=gray>(no composer.json in the folder named: auditing its enclosing project)</>',
            EnclosingProjectScope::line('/workspace', ['src/Controller', 'src/Entity']),
        );
    }

    public function test_it_names_the_folder_when_no_path_narrows_the_run(): void
    {
        self::assertSame(
            'Scope: <info>whole project</info> <fg=gray>(no composer.json in "/workspace": auditing its enclosing project)</>',
            EnclosingProjectScope::line('/workspace', []),
        );
    }
}
