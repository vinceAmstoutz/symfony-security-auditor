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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Config\Exception;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnreadableCredentialStoreException;

final class UnreadableCredentialStoreExceptionTest extends TestCase
{
    public function test_the_chmod_it_suggests_survives_a_path_with_spaces_and_quotes(): void
    {
        $message = UnreadableCredentialStoreException::forInsecurePermissions("/home/o'neil/my config/credentials.json", 0644)->getMessage();

        self::assertStringEndsWith(<<<'TEXT'
            then run "chmod 600 '/home/o'\''neil/my config/credentials.json'".
            TEXT, $message);
    }

    public function test_it_names_the_file_and_its_mode_as_they_are(): void
    {
        $message = UnreadableCredentialStoreException::forInsecurePermissions('/home/you/.config/symfony-security-auditor/credentials.json', 0644)->getMessage();

        self::assertStringStartsWith('The stored credentials at "/home/you/.config/symfony-security-auditor/credentials.json" are readable by other users on this machine (permissions 0644).', $message);
    }
}
