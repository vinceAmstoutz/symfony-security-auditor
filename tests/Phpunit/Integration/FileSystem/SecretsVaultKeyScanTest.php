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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\FileSystem;

use Override;
use PhpParser\ParserFactory;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\SecretScrubberInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\Exception\SecretScrubberConfigurationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\NullSecretScrubber;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\ProjectFileScanner;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\RegexSecretScrubber;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Tool\GrepTool;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Tool\ReadFileTool;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\FileSystem\Fixture\SodiumVaultKeyFile;

final class SecretsVaultKeyScanTest extends TestCase
{
    private const string KEY_FILE_IN_ANOTHER_SPELLING = <<<'PHP'
        <?php

        return 'K\'7
        z\\Q1';

        PHP;

    private string $tmpDir;

    private Filesystem $filesystem;

    /**
     * @throws SecretScrubberConfigurationException
     */
    #[DataProvider('vaultDirectories')]
    public function test_a_vault_decryption_key_file_holding_its_key_in_another_spelling_is_scanned_with_every_literal_redacted(string $directory): void
    {
        $content = $this->scannedVault($directory, self::KEY_FILE_IN_ANOTHER_SPELLING, new RegexSecretScrubber())[0]->content();

        self::assertSame("<?php\n\nreturn '***REDACTED:secrets_vault_key***\n';\n", $content);
        self::assertNotNull((new ParserFactory())->createForNewestSupportedVersion()->parse($content));
    }

    /**
     * @throws SecretScrubberConfigurationException
     */
    #[DataProvider('vaultDirectories')]
    public function test_a_vault_decryption_key_file_written_by_symfony_is_scanned_with_its_key_redacted_and_still_parses(string $directory): void
    {
        $content = $this->scannedVault($directory, SodiumVaultKeyFile::contents(SodiumVaultKeyFile::generatedKey()), new RegexSecretScrubber())[0]->content();

        self::assertSame(SodiumVaultKeyFile::redacted(), $content);
        self::assertNotNull((new ParserFactory())->createForNewestSupportedVersion()->parse($content));
    }

    /**
     * @throws SecretScrubberConfigurationException
     */
    public function test_the_file_tools_serve_a_vault_decryption_key_file_with_its_key_redacted(): void
    {
        $key = SodiumVaultKeyFile::generatedKey();
        $files = $this->scannedVault('config/secrets/prod', SodiumVaultKeyFile::contents($key), new RegexSecretScrubber());

        self::assertSame(SodiumVaultKeyFile::redacted(), (new ReadFileTool($files))->execute(['relative_path' => 'config/secrets/prod/prod.decrypt.private.php']));
        self::assertSame('No matches found.', (new GrepTool($files))->execute(['pattern' => SodiumVaultKeyFile::escaped($key)]));
        self::assertSame('No matches found.', (new GrepTool($files))->execute(['pattern' => base64_encode($key)]));
    }

    public function test_with_secret_scrubbing_disabled_a_vault_decryption_key_file_is_scanned_as_written(): void
    {
        $keyFile = SodiumVaultKeyFile::contents(SodiumVaultKeyFile::generatedKey());

        self::assertSame($keyFile, $this->scannedVault('config/secrets/prod', $keyFile, new NullSecretScrubber())[0]->content());
    }

    /** @return iterable<string, array{0: string}> */
    public static function vaultDirectories(): iterable
    {
        yield 'the default vault of an environment' => ['config/secrets/prod'];
        yield 'a vault in a directory of its own' => ['config/vault/staging'];
    }

    /**
     * @return list<ProjectFile> the key file, the one file of the project
     */
    private function scannedVault(string $directory, string $keyFile, SecretScrubberInterface $secretScrubber): array
    {
        $keyFilePath = \sprintf('%s/%s.decrypt.private.php', $directory, basename($directory));
        $this->filesystem->dumpFile(\sprintf('%s/%s', $this->tmpDir, $keyFilePath), $keyFile);

        $files = (new ProjectFileScanner(new NullLogger(), secretScrubber: $secretScrubber))->scan($this->tmpDir);

        self::assertSame([$keyFilePath], array_map(static fn (ProjectFile $projectFile): string => $projectFile->relativePath(), $files));

        return $files;
    }

    #[Override]
    protected function setUp(): void
    {
        $this->filesystem = new Filesystem();
        $this->tmpDir = sys_get_temp_dir().'/vault_key_scan_'.uniqid('', true);
        $this->filesystem->mkdir($this->tmpDir);
    }

    #[Override]
    protected function tearDown(): void
    {
        $this->filesystem->remove($this->tmpDir);
    }
}
