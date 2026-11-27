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
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\ConfiguredCredentialVariable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\XdgConfigPathResolver;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\CliAgentAccount;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\CliAgentAccountProbeInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuthTestCommand;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ConnectionCheckInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ProviderSetupReader;

final class AuthTestCommandTest extends TestCase
{
    public function test_it_reports_a_provider_that_answered(): void
    {
        $commandTester = $this->commandTester(null);

        $commandTester->execute([]);

        self::assertStringContainsString('[OK] The provider answered the test request. You can run an audit now.', $commandTester->getDisplay());
    }

    public function test_its_description_holds_for_a_platform_without_an_api_key(): void
    {
        self::assertStringNotContainsString('API key', AuthTestCommand::DESCRIPTION);
    }

    public function test_it_fails_with_the_reason_the_provider_gave(): void
    {
        $commandTester = $this->commandTester('HTTP 401: invalid x-api-key');

        $exitCode = $commandTester->execute([]);

        self::assertSame([Command::FAILURE, true], [$exitCode, str_contains((string) preg_replace('/\s+/', ' ', $commandTester->getDisplay()), 'The test failed, so an audit would fail too. The provider said: HTTP 401: invalid x-api-key')]);
    }

    public function test_it_names_the_provider_models_and_billed_account_it_tests(): void
    {
        $configHome = sys_get_temp_dir().'/ssa-auth-test-'.bin2hex(random_bytes(6));
        (new Filesystem())->dumpFile($configHome.'/symfony-security-auditor/config.yaml', "provider: codex\nplatform:\n    codex: {}\nmodel: gpt-6-luna\n");
        $cliAgentAccountProbe = self::createStub(CliAgentAccountProbeInterface::class);
        $cliAgentAccountProbe->method('probe')->willReturn(CliAgentAccount::subscription(null));
        $connectionCheck = self::createStub(ConnectionCheckInterface::class);
        $commandTester = new CommandTester(new AuthTestCommand($connectionCheck, new ProviderSetupReader(new ConfiguredCredentialVariable(new XdgConfigPathResolver($configHome, null, null)), $cliAgentAccountProbe)));

        $commandTester->execute([]);
        (new Filesystem())->remove($configHome);

        self::assertStringContainsString('Provider ChatGPT (through the Codex CLI) Model gpt-6-luna Billing your ChatGPT subscription', (string) preg_replace('/(?:\s|-{2,})+/', ' ', $commandTester->getDisplay()));
    }

    private function commandTester(?string $failureReason): CommandTester
    {
        $connectionCheck = self::createStub(ConnectionCheckInterface::class);
        $connectionCheck->method('failureReason')->willReturn($failureReason);

        return new CommandTester(new AuthTestCommand($connectionCheck));
    }
}
