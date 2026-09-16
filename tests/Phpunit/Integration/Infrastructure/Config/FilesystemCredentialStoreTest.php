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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Infrastructure\Config;

use Override;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\CredentialStoreWriteException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnreadableCredentialStoreException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\FilesystemCredentialStore;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\XdgConfigPathResolver;

final class FilesystemCredentialStoreTest extends TestCase
{
    private Filesystem $filesystem;

    private string $configHome;

    #[Override]
    protected function setUp(): void
    {
        $this->filesystem = new Filesystem();
        $this->configHome = sys_get_temp_dir().'/ssa-credentials-'.bin2hex(random_bytes(6));
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
    public function test_it_round_trips_a_credential(): void
    {
        $filesystemCredentialStore = $this->store();
        $filesystemCredentialStore->write('ANTHROPIC_API_KEY', 'sk-ant-api03-round-trip');

        self::assertSame('sk-ant-api03-round-trip', $filesystemCredentialStore->read('ANTHROPIC_API_KEY'));
    }

    /**
     * @throws CredentialStoreWriteException
     * @throws UnreadableCredentialStoreException
     */
    public function test_it_creates_the_credential_file_owner_only(): void
    {
        $this->store()->write('ANTHROPIC_API_KEY', 'sk-ant-api03-owner-only');

        self::assertSame('0600', $this->permissionsOf($this->credentialsFile()));
    }

    /**
     * @throws CredentialStoreWriteException
     * @throws UnreadableCredentialStoreException
     */
    public function test_it_creates_the_configuration_directory_owner_only(): void
    {
        $this->store()->write('ANTHROPIC_API_KEY', 'sk-ant-api03-owner-only');

        self::assertSame('0700', $this->permissionsOf(\dirname($this->credentialsFile())));
    }

    /**
     * @throws CredentialStoreWriteException
     * @throws UnreadableCredentialStoreException
     */
    public function test_it_tightens_permissions_a_previous_write_left_open(): void
    {
        $filesystemCredentialStore = $this->store();
        $filesystemCredentialStore->write('ANTHROPIC_API_KEY', 'sk-ant-api03-first');
        $this->filesystem->chmod($this->credentialsFile(), 0644);

        $filesystemCredentialStore->write('OPENAI_API_KEY', 'sk-proj-second');

        self::assertSame('0600', $this->permissionsOf($this->credentialsFile()));
    }

    /**
     * @throws UnreadableCredentialStoreException
     */
    public function test_it_refuses_to_read_a_credential_file_other_users_can_open(): void
    {
        $this->givenStoredCredentials('{"ANTHROPIC_API_KEY":"sk-ant-api03-exposed"}', 0644);

        $this->expectException(UnreadableCredentialStoreException::class);
        $this->expectExceptionMessage('readable by other users on this machine (permissions 0644)');

        $this->store()->read('ANTHROPIC_API_KEY');
    }

    /**
     * @throws UnreadableCredentialStoreException
     */
    public function test_it_reads_a_credential_file_windows_cannot_express_permissions_for(): void
    {
        $this->givenStoredCredentials('{"ANTHROPIC_API_KEY":"sk-ant-api03-windows"}', 0644);

        self::assertSame('sk-ant-api03-windows', $this->store('Windows')->read('ANTHROPIC_API_KEY'));
    }

    /**
     * @throws UnreadableCredentialStoreException
     */
    public function test_it_reports_no_credential_when_nothing_was_ever_stored(): void
    {
        self::assertNull($this->store()->read('ANTHROPIC_API_KEY'));
    }

    /**
     * @throws UnreadableCredentialStoreException
     */
    public function test_it_reports_no_credential_for_an_unstored_variable(): void
    {
        $this->givenStoredCredentials('{"ANTHROPIC_API_KEY":"sk-ant-api03-stored"}');

        self::assertNull($this->store()->read('OPENAI_API_KEY'));
    }

    /**
     * @throws UnreadableCredentialStoreException
     */
    public function test_it_reports_no_credential_for_a_blank_entry(): void
    {
        $this->givenStoredCredentials('{"ANTHROPIC_API_KEY":""}');

        self::assertNull($this->store()->read('ANTHROPIC_API_KEY'));
    }

    /**
     * @throws UnreadableCredentialStoreException
     */
    public function test_it_ignores_entries_that_are_not_credential_strings(): void
    {
        $this->givenStoredCredentials('{"ANTHROPIC_API_KEY":{"nested":"object"}}');

        self::assertNull($this->store()->read('ANTHROPIC_API_KEY'));
    }

    /**
     * @throws UnreadableCredentialStoreException
     */
    public function test_it_treats_a_credential_file_holding_nothing_yet_as_empty(): void
    {
        $this->givenStoredCredentials('');

        self::assertNull($this->store()->read('ANTHROPIC_API_KEY'));
    }

    #[DataProvider('unparsableCredentialFiles')]
    public function test_it_refuses_to_guess_at_a_credential_file_it_cannot_parse(string $contents): void
    {
        $this->givenStoredCredentials($contents);

        $this->expectException(UnreadableCredentialStoreException::class);
        $this->expectExceptionMessage('are not valid JSON');

        $this->store()->read('ANTHROPIC_API_KEY');
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function unparsableCredentialFiles(): iterable
    {
        yield 'truncated json' => ['{"ANTHROPIC_API_KEY":'];
        yield 'a bare scalar' => ['"sk-ant-api03-bare"'];
    }

    /**
     * @throws CredentialStoreWriteException
     * @throws UnreadableCredentialStoreException
     */
    public function test_it_keeps_credentials_for_other_variables_when_one_is_written(): void
    {
        $filesystemCredentialStore = $this->store();
        $filesystemCredentialStore->write('ANTHROPIC_API_KEY', 'sk-ant-api03-kept');
        $filesystemCredentialStore->write('OPENAI_API_KEY', 'sk-proj-added');

        self::assertSame('sk-ant-api03-kept', $filesystemCredentialStore->read('ANTHROPIC_API_KEY'));
    }

    /**
     * @throws CredentialStoreWriteException
     * @throws UnreadableCredentialStoreException
     */
    public function test_it_replaces_a_credential_stored_under_the_same_variable(): void
    {
        $filesystemCredentialStore = $this->store();
        $filesystemCredentialStore->write('ANTHROPIC_API_KEY', 'sk-ant-api03-old');
        $filesystemCredentialStore->write('ANTHROPIC_API_KEY', 'sk-ant-api03-new');

        self::assertSame('sk-ant-api03-new', $filesystemCredentialStore->read('ANTHROPIC_API_KEY'));
    }

    /**
     * @throws CredentialStoreWriteException
     * @throws UnreadableCredentialStoreException
     */
    public function test_it_removes_a_stored_credential(): void
    {
        $filesystemCredentialStore = $this->store();
        $filesystemCredentialStore->write('ANTHROPIC_API_KEY', 'sk-ant-api03-removed');
        $filesystemCredentialStore->remove('ANTHROPIC_API_KEY');

        self::assertNull($filesystemCredentialStore->read('ANTHROPIC_API_KEY'));
    }

    /**
     * @throws CredentialStoreWriteException
     * @throws UnreadableCredentialStoreException
     */
    public function test_it_reports_that_a_credential_was_removed(): void
    {
        $filesystemCredentialStore = $this->store();
        $filesystemCredentialStore->write('ANTHROPIC_API_KEY', 'sk-ant-api03-removed');

        self::assertTrue($filesystemCredentialStore->remove('ANTHROPIC_API_KEY'));
    }

    /**
     * @throws CredentialStoreWriteException
     * @throws UnreadableCredentialStoreException
     */
    public function test_it_reports_that_nothing_was_removed_for_an_unstored_variable(): void
    {
        self::assertFalse($this->store()->remove('ANTHROPIC_API_KEY'));
    }

    /**
     * @throws CredentialStoreWriteException
     * @throws UnreadableCredentialStoreException
     */
    public function test_it_keeps_other_credentials_when_one_is_removed(): void
    {
        $filesystemCredentialStore = $this->store();
        $filesystemCredentialStore->write('ANTHROPIC_API_KEY', 'sk-ant-api03-kept');
        $filesystemCredentialStore->write('OPENAI_API_KEY', 'sk-proj-dropped');
        $filesystemCredentialStore->remove('OPENAI_API_KEY');

        self::assertSame('sk-ant-api03-kept', $filesystemCredentialStore->read('ANTHROPIC_API_KEY'));
    }

    #[DataProvider('unstorableCredentials')]
    public function test_it_refuses_to_store_a_credential_it_could_not_read_back(string $credential, string $expectedMessage): void
    {
        $this->expectException(CredentialStoreWriteException::class);
        $this->expectExceptionMessage($expectedMessage);

        $this->store()->write('ANTHROPIC_API_KEY', $credential);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function unstorableCredentials(): iterable
    {
        yield 'empty' => ['', 'An empty API key cannot be stored.'];
        yield 'invalid utf-8' => ["sk-ant-\xc3\x28", 'must be valid UTF-8 text'];
    }

    /**
     * @throws CredentialStoreWriteException
     * @throws UnreadableCredentialStoreException
     */
    public function test_it_reports_where_credentials_are_kept(): void
    {
        self::assertSame($this->credentialsFile(), $this->store()->location());
    }

    /**
     * @throws CredentialStoreWriteException
     * @throws UnreadableCredentialStoreException
     */
    public function test_it_reports_no_location_when_no_configuration_directory_can_be_resolved(): void
    {
        self::assertNull($this->homelessStore()->location());
    }

    /**
     * @throws CredentialStoreWriteException
     * @throws UnreadableCredentialStoreException
     */
    public function test_it_reports_no_credential_when_no_configuration_directory_can_be_resolved(): void
    {
        self::assertNull($this->homelessStore()->read('ANTHROPIC_API_KEY'));
    }

    public function test_it_refuses_to_store_a_credential_with_nowhere_to_put_it(): void
    {
        $this->expectException(CredentialStoreWriteException::class);
        $this->expectExceptionMessage('No per-user configuration directory could be resolved');

        $this->homelessStore()->write('ANTHROPIC_API_KEY', 'sk-ant-api03-homeless');
    }

    /**
     * @throws UnreadableCredentialStoreException
     */
    public function test_it_reports_a_credential_file_it_cannot_open(): void
    {
        $this->filesystem->mkdir($this->credentialsFile());
        $this->filesystem->chmod($this->credentialsFile(), 0700);

        $this->expectException(UnreadableCredentialStoreException::class);
        $this->expectExceptionMessage('could not be read');

        $this->store()->read('ANTHROPIC_API_KEY');
    }

    public function test_it_reports_a_credential_file_it_cannot_write(): void
    {
        $this->filesystem->dumpFile(\dirname($this->credentialsFile()), 'a file where the configuration directory belongs');

        $this->expectException(CredentialStoreWriteException::class);
        $this->expectExceptionMessage('could not be written');

        $this->store()->write('ANTHROPIC_API_KEY', 'sk-ant-api03-blocked');
    }

    private function givenStoredCredentials(string $contents, int $mode = 0600): void
    {
        $this->filesystem->dumpFile($this->credentialsFile(), $contents);
        $this->filesystem->chmod($this->credentialsFile(), $mode);
    }

    private function credentialsFile(): string
    {
        return \sprintf('%s/symfony-security-auditor/credentials.json', $this->configHome);
    }

    private function permissionsOf(string $path): string
    {
        clearstatcache(true, $path);
        $permissions = fileperms($path);
        self::assertNotFalse($permissions);

        return \sprintf('%04o', $permissions & 0777);
    }

    private function homelessStore(): FilesystemCredentialStore
    {
        return new FilesystemCredentialStore(new XdgConfigPathResolver(null, null, null), $this->filesystem);
    }

    private function store(string $osFamily = 'Linux'): FilesystemCredentialStore
    {
        return new FilesystemCredentialStore(
            new XdgConfigPathResolver($this->configHome, null, null),
            $this->filesystem,
            $osFamily,
        );
    }
}
