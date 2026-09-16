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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\CredentialStoreWriteException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnreadableCredentialStoreException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\FilesystemCredentialStore;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\XdgConfigPathResolver;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuthSetCommand;

final class AuthSetCommandTest extends TestCase
{
    private Filesystem $filesystem;

    private string $configHome;

    #[Override]
    protected function setUp(): void
    {
        $this->filesystem = new Filesystem();
        $this->configHome = sys_get_temp_dir().'/ssa-auth-set-'.bin2hex(random_bytes(6));
    }

    #[Override]
    protected function tearDown(): void
    {
        $this->filesystem->remove($this->configHome);
    }

    /**
     * @throws UnreadableCredentialStoreException
     */
    public function test_it_stores_the_key_under_the_variable_the_configuration_reads(): void
    {
        $this->writeConfig();
        $commandTester = $this->commandTester();
        $commandTester->setInputs(['anthropic-test-key-typed-by-hand']);

        $commandTester->execute([]);

        self::assertSame('anthropic-test-key-typed-by-hand', $this->store()->read('ANTHROPIC_API_KEY'));
    }

    /**
     * @throws UnreadableCredentialStoreException
     */
    public function test_it_stores_the_key_under_a_variable_named_on_the_command_line(): void
    {
        $this->writeConfig();
        $commandTester = $this->commandTester();
        $commandTester->setInputs(['openai-test-key-typed-by-hand']);

        $commandTester->execute(['--env-var' => 'OPENAI_API_KEY']);

        self::assertSame('openai-test-key-typed-by-hand', $this->store()->read('OPENAI_API_KEY'));
    }

    /**
     * @throws UnreadableCredentialStoreException
     */
    public function test_it_drops_the_whitespace_a_paste_brings_with_it(): void
    {
        $this->writeConfig();
        $commandTester = $this->commandTester();
        $commandTester->setInputs(['  anthropic-test-key-pasted  ']);

        $commandTester->execute([]);

        self::assertSame('anthropic-test-key-pasted', $this->store()->read('ANTHROPIC_API_KEY'));
    }

    /**
     * @throws CredentialStoreWriteException
     * @throws UnreadableCredentialStoreException
     */
    public function test_it_replaces_a_key_stored_earlier(): void
    {
        $this->writeConfig();
        $this->store()->write('ANTHROPIC_API_KEY', 'anthropic-test-key-the-old-one');
        $commandTester = $this->commandTester();
        $commandTester->setInputs(['anthropic-test-key-the-new-one']);

        $commandTester->execute([]);

        self::assertSame('anthropic-test-key-the-new-one', $this->store()->read('ANTHROPIC_API_KEY'));
    }

    public function test_it_names_the_stored_key_without_printing_it(): void
    {
        $this->writeConfig();
        $commandTester = $this->commandTester();
        $commandTester->setInputs(['anthropic-test-key-for-previews']);

        $commandTester->execute([]);

        $display = $this->flattened($commandTester);

        self::assertStringContainsString('Stored ANTHROPIC_API_KEY (anthro…iews, SHA256:66ff24e605fe0e69)', $display);
        self::assertStringNotContainsString('anthropic-test-key-for-previews', $display);
    }

    public function test_it_says_where_the_key_landed(): void
    {
        $this->writeConfig();
        $commandTester = $this->commandTester();
        $commandTester->setInputs(['anthropic-test-key-typed-by-hand']);

        $commandTester->execute([]);

        self::assertStringContainsString($this->configHome.'/symfony-security-auditor/credentials.json', $this->flattened($commandTester));
    }

    public function test_it_refuses_when_no_variable_is_configured_yet(): void
    {
        $commandTester = $this->commandTester();

        self::assertSame(Command::INVALID, $commandTester->execute([], ['interactive' => false]));
    }

    public function test_it_points_an_unconfigured_user_at_init(): void
    {
        $commandTester = $this->commandTester();
        $commandTester->execute([], ['interactive' => false]);

        self::assertStringContainsString('Run "init" first', $this->flattened($commandTester));
    }

    public function test_it_refuses_an_empty_answer_rather_than_storing_nothing(): void
    {
        $this->writeConfig();
        $commandTester = $this->commandTester();
        $commandTester->setInputs(['   ']);

        self::assertSame(Command::INVALID, $commandTester->execute([]));
    }

    public function test_it_offers_the_environment_variable_when_it_cannot_prompt(): void
    {
        $this->writeConfig();
        $commandTester = $this->commandTester();
        $commandTester->execute([], ['interactive' => false]);

        self::assertStringContainsString('export ANTHROPIC_API_KEY instead', $this->flattened($commandTester));
    }

    private function flattened(CommandTester $commandTester): string
    {
        return (string) preg_replace('/\s+/', ' ', $commandTester->getDisplay());
    }

    private function writeConfig(): void
    {
        $this->filesystem->dumpFile($this->configHome.'/symfony-security-auditor/config.yaml', "platform:\n    anthropic:\n        api_key: '%env(ANTHROPIC_API_KEY)%'\n");
    }

    private function commandTester(): CommandTester
    {
        $xdgConfigPathResolver = new XdgConfigPathResolver($this->configHome, null, null);

        return new CommandTester(new AuthSetCommand(
            new FilesystemCredentialStore($xdgConfigPathResolver),
            new ConfiguredCredentialVariable($xdgConfigPathResolver),
        ));
    }

    private function store(): FilesystemCredentialStore
    {
        return new FilesystemCredentialStore(new XdgConfigPathResolver($this->configHome, null, null));
    }
}
