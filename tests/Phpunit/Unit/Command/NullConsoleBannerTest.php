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
use Symfony\Component\Console\Output\BufferedOutput;
use VinceAmstoutz\SymfonySecurityAuditor\Command\NullConsoleBanner;

final class NullConsoleBannerTest extends TestCase
{
    public function test_it_writes_nothing_at_all(): void
    {
        $bufferedOutput = new BufferedOutput();

        (new NullConsoleBanner())->render($bufferedOutput);

        self::assertSame('', $bufferedOutput->fetch());
    }
}
