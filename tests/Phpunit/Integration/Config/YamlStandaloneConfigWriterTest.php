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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Config;

use Override;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Yaml\Yaml;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\StandaloneConfigWriteException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\YamlStandaloneConfigWriter;

final class YamlStandaloneConfigWriterTest extends TestCase
{
    private string $configFile;

    #[Override]
    protected function setUp(): void
    {
        $this->configFile = sys_get_temp_dir().'/ssa-write-'.bin2hex(random_bytes(6)).'/config.yaml';
    }

    #[Override]
    protected function tearDown(): void
    {
        (new Filesystem())->remove(\dirname($this->configFile));
    }

    /**
     * @throws StandaloneConfigWriteException
     */
    public function test_it_writes_the_configuration_as_parseable_yaml(): void
    {
        $config = ['provider' => 'anthropic', 'platform' => ['anthropic' => ['api_key' => '%env(ANTHROPIC_API_KEY)%']], 'model' => 'claude-opus-4-8'];

        (new YamlStandaloneConfigWriter())->write($this->configFile, $config);

        self::assertSame($config, Yaml::parseFile($this->configFile));
    }

    /**
     * @throws StandaloneConfigWriteException
     */
    public function test_it_restricts_the_config_file_to_owner_only_permissions(): void
    {
        (new YamlStandaloneConfigWriter())->write($this->configFile, ['model' => 'claude-opus-4-8']);

        $permissions = fileperms($this->configFile);
        self::assertNotFalse($permissions);
        self::assertSame('0600', substr(\sprintf('%o', $permissions), -4));
    }

    /**
     * @throws StandaloneConfigWriteException
     */
    public function test_the_config_file_already_has_owner_only_permissions_before_its_content_is_written(): void
    {
        $filesystem = new class extends Filesystem {
            public ?int $permissionsAtDumpFileStart = null;

            /**
             * @param resource|string $content
             */
            #[Override]
            public function dumpFile(string $filename, $content): void
            {
                $this->permissionsAtDumpFileStart = file_exists($filename) ? fileperms($filename) & 0o777 : null;
                parent::dumpFile($filename, $content);
            }
        };

        (new YamlStandaloneConfigWriter($filesystem))->write($this->configFile, ['model' => 'claude-opus-4-8']);

        self::assertSame(0o600, $filesystem->permissionsAtDumpFileStart);
    }

    /**
     * @throws StandaloneConfigWriteException
     */
    public function test_it_wraps_an_io_failure_as_a_standalone_config_write_exception(): void
    {
        $filesystem = new Filesystem();
        $blockingFile = \dirname($this->configFile).'/not-a-directory';
        $filesystem->mkdir(\dirname($blockingFile));
        $filesystem->dumpFile($blockingFile, 'x');

        $this->expectException(StandaloneConfigWriteException::class);

        (new YamlStandaloneConfigWriter())->write($blockingFile.'/config.yaml', ['model' => 'claude-opus-4-8']);
    }
}
