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
use Symfony\Component\Filesystem\Exception\IOException;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\ConfiguredCredentialVariable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\CredentialStoreWriteException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnreadableCredentialStoreException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\FilesystemCredentialStore;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\XdgConfigPathResolver;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuthRemoveCommand;

final class AuthRemoveCommandTest extends TestCase
{
    private Filesystem $filesystem;

    private string $configHome;

    #[Override]
    protected function setUp(): void
    {
        $this->filesystem = new Filesystem();
        $this->configHome = sys_get_temp_dir().'/ssa-auth-remove-'.bin2hex(random_bytes(6));
    }

    #[Override]
    protected function tearDown(): void
    {
        $this->filesystem->remove($this->configHome);
    }

    /**
     * @throws CredentialStoreWriteException
     * @throws UnreadableCredentialStoreException
     */
    public function test_it_forgets_the_stored_key(): void
    {
        $this->writeConfig();
        $this->store()->write('ANTHROPIC_API_KEY', 'anthropic-test-key-to-forget');

        $this->commandTester()->execute([]);

        self::assertNull($this->store()->read('ANTHROPIC_API_KEY'));
    }

    /**
     * @throws CredentialStoreWriteException
     * @throws UnreadableCredentialStoreException
     */
    public function test_it_reminds_the_user_to_revoke_the_key_with_the_provider(): void
    {
        $this->writeConfig();
        $this->store()->write('ANTHROPIC_API_KEY', 'anthropic-test-key-to-forget');
        $commandTester = $this->commandTester();

        $commandTester->execute([]);

        self::assertStringContainsString('revoke it there too', $this->flattened($commandTester));
    }

    /**
     * @throws CredentialStoreWriteException
     * @throws UnreadableCredentialStoreException
     */
    public function test_it_forgets_a_key_stored_under_a_variable_named_on_the_command_line(): void
    {
        $this->writeConfig();
        $this->store()->write('OPENAI_API_KEY', 'openai-test-key-to-forget');

        $this->commandTester()->execute(['--env-var' => 'OPENAI_API_KEY']);

        self::assertNull($this->store()->read('OPENAI_API_KEY'));
    }

    public function test_it_says_when_there_was_nothing_stored(): void
    {
        $this->writeConfig();
        $commandTester = $this->commandTester();

        $commandTester->execute([]);

        self::assertStringContainsString('Nothing was stored for ANTHROPIC_API_KEY', $this->flattened($commandTester));
    }

    public function test_it_does_not_claim_to_have_forgotten_a_key_that_was_never_stored(): void
    {
        $this->writeConfig();
        $commandTester = $this->commandTester();

        $commandTester->execute([]);

        self::assertStringNotContainsString('Forgot the stored key', $this->flattened($commandTester));
    }

    public function test_it_succeeds_when_there_was_nothing_stored(): void
    {
        $this->writeConfig();

        self::assertSame(Command::SUCCESS, $this->commandTester()->execute([]));
    }

    public function test_it_refuses_when_no_variable_is_configured_yet(): void
    {
        self::assertSame(Command::INVALID, $this->commandTester()->execute([]));
    }

    public function test_it_tells_an_unconfigured_user_how_to_name_the_variable(): void
    {
        $commandTester = $this->commandTester();
        $commandTester->execute([]);

        self::assertStringContainsString('Name one explicitly with --env-var', $this->flattened($commandTester));
    }

    private function flattened(CommandTester $commandTester): string
    {
        return (string) preg_replace('/\s+/', ' ', $commandTester->getDisplay());
    }

    private function writeConfig(): void
    {
        $this->filesystem->dumpFile($this->configHome.'/symfony-security-auditor/config.yaml', "platform:\n    anthropic:\n        api_key: '%env(ANTHROPIC_API_KEY)%'\n");
    }

    public function test_it_reports_a_store_it_cannot_parse_instead_of_crashing(): void
    {
        $this->filesystem->dumpFile($this->configHome.'/symfony-security-auditor/credentials.json', '{not json');
        $this->filesystem->chmod($this->configHome.'/symfony-security-auditor/credentials.json', 0600);

        $commandTester = $this->commandTester();

        self::assertSame(Command::FAILURE, $commandTester->execute(['--env-var' => 'ANTHROPIC_API_KEY']));
        self::assertStringContainsString('are not valid JSON. Run "auth:set" to write them again.', (string) preg_replace('/\s+/', ' ', $commandTester->getDisplay()));
    }

    /**
     * @throws CredentialStoreWriteException
     * @throws UnreadableCredentialStoreException
     */
    public function test_it_reports_a_store_it_cannot_rewrite_instead_of_crashing(): void
    {
        $this->store()->write('ANTHROPIC_API_KEY', 'anthropic-test-key-to-forget');
        $xdgConfigPathResolver = new XdgConfigPathResolver($this->configHome, null, null);
        $commandTester = new CommandTester(new AuthRemoveCommand(
            new FilesystemCredentialStore($xdgConfigPathResolver, new class extends Filesystem {
                #[Override]
                public function dumpFile(string $filename, $content): void
                {
                    throw new IOException(\sprintf('Failed to write "%s".', $filename));
                }
            }),
            new ConfiguredCredentialVariable($xdgConfigPathResolver),
        ));

        self::assertSame(Command::FAILURE, $commandTester->execute(['--env-var' => 'ANTHROPIC_API_KEY']));
        self::assertStringContainsString('could not be written.', (string) preg_replace('/\s+/', ' ', $commandTester->getDisplay()));
    }

    private function commandTester(): CommandTester
    {
        $xdgConfigPathResolver = new XdgConfigPathResolver($this->configHome, null, null);

        return new CommandTester(new AuthRemoveCommand(
            new FilesystemCredentialStore($xdgConfigPathResolver),
            new ConfiguredCredentialVariable($xdgConfigPathResolver),
        ));
    }

    private function store(): FilesystemCredentialStore
    {
        return new FilesystemCredentialStore(new XdgConfigPathResolver($this->configHome, null, null));
    }

    public function test_it_refuses_a_name_no_environment_variable_can_have(): void
    {
        $this->writeConfig();

        self::assertSame(Command::INVALID, $this->commandTester()->execute(['--env-var' => 'not-a-var']));
    }

    public function test_it_says_what_a_valid_variable_name_looks_like(): void
    {
        $this->writeConfig();
        $commandTester = $this->commandTester();

        $commandTester->execute(['--env-var' => 'not-a-var']);

        self::assertStringContainsString('"not-a-var" is not a valid environment variable name', $this->flattened($commandTester));
    }

    public function test_it_refuses_a_relative_home_override_instead_of_reporting_no_directory(): void
    {
        $xdgConfigPathResolver = new XdgConfigPathResolver(null, null, null, null, 'relative/home');
        $commandTester = new CommandTester(new AuthRemoveCommand(
            new FilesystemCredentialStore($xdgConfigPathResolver),
            new ConfiguredCredentialVariable($xdgConfigPathResolver),
        ));

        self::assertSame(Command::FAILURE, $commandTester->execute(['--env-var' => 'ANTHROPIC_API_KEY']));
        self::assertStringContainsString('SYMFONY_SECURITY_AUDITOR_HOME is set to "relative/home", which is not an absolute path', (string) preg_replace('/\s+/', ' ', $commandTester->getDisplay()));
        self::assertSame(1, substr_count($commandTester->getDisplay(), '[ERROR]'), $commandTester->getDisplay());
        self::assertStringNotContainsString('ANTHROPIC_API_KEY', $commandTester->getDisplay());
    }
}
