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
use VinceAmstoutz\SymfonySecurityAuditor\Command\StandardOutput;

final class StandardOutputTest extends TestCase
{
    public function test_it_tells_whether_this_process_prints_to_a_terminal(): void
    {
        self::assertSame(stream_isatty(\STDOUT), (new StandardOutput())->isTerminal());
    }
}
