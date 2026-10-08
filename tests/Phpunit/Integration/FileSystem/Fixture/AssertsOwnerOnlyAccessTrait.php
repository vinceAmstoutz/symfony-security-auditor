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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\FileSystem\Fixture;

trait AssertsOwnerOnlyAccessTrait
{
    private static function assertOwnerOnlyFile(string $path): void
    {
        self::assertSame('0600', self::permissionsOf($path), \sprintf('"%s" must be readable by its owner only', $path));
    }

    private static function assertOwnerOnlyDirectory(string $path): void
    {
        self::assertSame('0700', self::permissionsOf($path), \sprintf('"%s" must be accessible to its owner only', $path));
    }

    private static function permissionsOf(string $path): string
    {
        $permissions = fileperms($path);
        self::assertNotFalse($permissions, \sprintf('"%s" must exist', $path));

        return substr(\sprintf('%o', $permissions), -4);
    }
}
