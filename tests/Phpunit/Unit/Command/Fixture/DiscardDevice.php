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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Command\Fixture;

/**
 * Test fixture: a character device that discards what is written to it. A
 * private node is made where the process may create one, so a regression that
 * replaced the device never touches `/dev/null`; elsewhere the real one is
 * returned, which a process that cannot write `/dev` cannot replace either.
 */
final readonly class DiscardDevice
{
    public static function in(string $directory): string
    {
        $device = $directory.'/discard';

        return posix_mknod($device, \POSIX_S_IFCHR | 0o666, 1, 3) ? $device : '/dev/null';
    }
}
