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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Command;

use Override;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\ConfiguredCredentialVariable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\FilesystemCredentialStore;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\XdgConfigPathResolver;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuthStatusCommand;

final class AuthStatusCommandTest extends TestCase
{
    private const string KEY = 'anthropic-test-key-for-previews';

    private Filesystem $filesystem;

    private string $configHome;

    #[Override]
    protected function setUp(): void
    {
        $this->filesystem = new Filesystem();
        $this->configHome = sys_get_temp_dir().'/ssa-auth-status-'.bin2hex(random_bytes(6));
    }

    #[Override]
    protected function tearDown(): void
    {
        $this->filesystem->remove($this->configHome);
    }

    public function test_it_reports_a_key_coming_from_the_environment(): void
    {
        $this->writeConfig();
        $commandTester = $this->commandTester(['ANTHROPIC_API_KEY' => self::KEY]);

        $commandTester->execute([]);

        self::assertStringContainsString('Source the environment', $this->flattened($commandTester));
    }

    public function test_it_reports_a_key_coming_from_the_store(): void
    {
        $this->writeConfig();
        $this->store()->write('ANTHROPIC_API_KEY', self::KEY);
        $commandTester = $this->commandTester();

        $commandTester->execute([]);

        self::assertStringContainsString('Source stored on this machine', $this->flattened($commandTester));
    }

    public function test_it_names_the_key_without_printing_it(): void
    {
        $this->writeConfig();
        $this->store()->write('ANTHROPIC_API_KEY', self::KEY);
        $commandTester = $this->commandTester();

        $commandTester->execute([]);

        $display = $this->flattened($commandTester);

        self::assertStringContainsString('Key anthro…iews Fingerprint SHA256:66ff24e605fe0e69', $display);
        self::assertStringNotContainsString(self::KEY, $display);
    }

    public function test_it_warns_that_an_exported_variable_shadows_the_stored_key(): void
    {
        $this->writeConfig();
        $this->store()->write('ANTHROPIC_API_KEY', self::KEY);
        $commandTester = $this->commandTester(['ANTHROPIC_API_KEY' => 'anthropic-test-key-exported']);

        $commandTester->execute([]);

        self::assertStringContainsString('A key is also stored on this machine, but the exported ANTHROPIC_API_KEY wins', $this->flattened($commandTester));
    }

    public function test_it_stays_quiet_about_shadowing_when_nothing_is_stored(): void
    {
        $this->writeConfig();
        $commandTester = $this->commandTester(['ANTHROPIC_API_KEY' => self::KEY]);

        $commandTester->execute([]);

        self::assertStringNotContainsString('is also stored on this machine', $this->flattened($commandTester));
    }

    public function test_it_reports_a_variable_named_on_the_command_line(): void
    {
        $commandTester = $this->commandTester(['OPENAI_API_KEY' => self::KEY]);

        $commandTester->execute(['--env-var' => 'OPENAI_API_KEY']);

        self::assertStringContainsString('Variable OPENAI_API_KEY', $this->flattened($commandTester));
    }

    public function test_it_fails_when_no_key_resolves_at_all(): void
    {
        $this->writeConfig();

        self::assertSame(Command::FAILURE, $this->commandTester()->execute([]));
    }

    public function test_it_offers_every_way_of_supplying_a_missing_key(): void
    {
        $this->writeConfig();
        $commandTester = $this->commandTester();

        $commandTester->execute([]);

        $display = $this->flattened($commandTester);

        self::assertStringContainsString('auth:set', $display);
        self::assertStringContainsString('export ANTHROPIC_API_KEY=', $display);
        self::assertStringContainsString('ANTHROPIC_API_KEY=$(pass show …) audit .', $display);
    }

    public function test_it_refuses_when_no_variable_is_configured_yet(): void
    {
        self::assertSame(Command::INVALID, $this->commandTester()->execute([]));
    }

    public function test_it_points_an_unconfigured_user_at_init(): void
    {
        $commandTester = $this->commandTester();
        $commandTester->execute([]);

        self::assertStringContainsString('Run "init" to create a configuration', $this->flattened($commandTester));
    }

    public function test_it_says_when_credentials_have_nowhere_to_live(): void
    {
        $commandTester = new CommandTester(new AuthStatusCommand(
            new FilesystemCredentialStore(new XdgConfigPathResolver(null, null, null)),
            new ConfiguredCredentialVariable(new XdgConfigPathResolver(null, null, null)),
            ['ANTHROPIC_API_KEY' => self::KEY],
        ));

        $commandTester->execute(['--env-var' => 'ANTHROPIC_API_KEY']);

        self::assertStringContainsString('no per-user configuration directory could be resolved', $this->flattened($commandTester));
    }

    /**
     * Collapses the block gutter SymfonyStyle draws down the left of a note,
     * so an assertion reads the sentence rather than where it happened to wrap.
     */
    private function flattened(CommandTester $commandTester): string
    {
        return (string) preg_replace('/[\s!]+/', ' ', $commandTester->getDisplay());
    }

    private function writeConfig(): void
    {
        $this->filesystem->dumpFile($this->configHome.'/symfony-security-auditor/config.yaml', "platform:\n    anthropic:\n        api_key: '%env(ANTHROPIC_API_KEY)%'\n");
    }

    /**
     * @param array<string, string> $environment
     */
    private function commandTester(array $environment = []): CommandTester
    {
        $xdgConfigPathResolver = new XdgConfigPathResolver($this->configHome, null, null);

        return new CommandTester(new AuthStatusCommand(
            new FilesystemCredentialStore($xdgConfigPathResolver),
            new ConfiguredCredentialVariable($xdgConfigPathResolver),
            $environment,
        ));
    }

    private function store(): FilesystemCredentialStore
    {
        return new FilesystemCredentialStore(new XdgConfigPathResolver($this->configHome, null, null));
    }
}
