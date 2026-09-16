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
use VinceAmstoutz\SymfonySecurityAuditor\Command\CredentialConsoleBanner;

final class CredentialConsoleBannerTest extends TestCase
{
    public function test_it_names_the_key_the_run_will_spend(): void
    {
        $bufferedOutput = new BufferedOutput();

        (new CredentialConsoleBanner('sk-ant…qF4A'))->render($bufferedOutput);

        self::assertSame("API key: sk-ant…qF4A\n", $bufferedOutput->fetch());
    }

    public function test_it_neutralises_markup_a_credential_preview_could_carry(): void
    {
        $bufferedOutput = new BufferedOutput();

        (new CredentialConsoleBanner('sk-<in…fo>'))->render($bufferedOutput);

        self::assertSame("API key: sk-<in…fo>\n", $bufferedOutput->fetch());
    }
}
