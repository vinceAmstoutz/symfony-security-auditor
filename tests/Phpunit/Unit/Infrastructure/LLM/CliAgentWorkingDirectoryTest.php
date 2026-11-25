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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\LLM;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\CliAgentWorkingDirectory;

final class CliAgentWorkingDirectoryTest extends TestCase
{
    public function test_it_is_a_fresh_directory_of_the_temp_directory_only_its_owner_can_open(): void
    {
        $cliAgentWorkingDirectory = new CliAgentWorkingDirectory();

        self::assertMatchesRegularExpression('#^'.preg_quote(sys_get_temp_dir(), '#').'/symfony-security-auditor-cli-[0-9a-f]{32}$#', $cliAgentWorkingDirectory->path);
        self::assertDirectoryExists($cliAgentWorkingDirectory->path);
        self::assertSame(0o700, fileperms($cliAgentWorkingDirectory->path) & 0o777);
    }

    public function test_it_is_removed_with_what_the_cli_left_in_it_once_nothing_holds_it(): void
    {
        $cliAgentWorkingDirectory = new CliAgentWorkingDirectory();
        $path = $cliAgentWorkingDirectory->path;
        file_put_contents($path.'/session.json', '{}');

        unset($cliAgentWorkingDirectory);

        self::assertDirectoryDoesNotExist($path);
    }
}
