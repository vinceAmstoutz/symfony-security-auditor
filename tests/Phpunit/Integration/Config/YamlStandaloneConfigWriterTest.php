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
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Yaml\Yaml;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\StandaloneConfigWriteException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnsafeStandaloneConfigWriteException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandaloneConfigFileReader;
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
     * @throws UnsafeStandaloneConfigWriteException
     */
    public function test_it_writes_the_configuration_as_parseable_yaml(): void
    {
        $config = ['provider' => 'anthropic', 'platform' => ['anthropic' => ['api_key' => '%env(ANTHROPIC_API_KEY)%']], 'model' => 'claude-opus-4-8'];

        (new YamlStandaloneConfigWriter())->write($this->configFile, $config);

        self::assertSame($config, Yaml::parseFile($this->configFile));
    }

    /**
     * @throws StandaloneConfigWriteException
     * @throws UnsafeStandaloneConfigWriteException
     */
    public function test_it_leaves_ordinary_values_as_plain_as_a_person_would_write_them(): void
    {
        (new YamlStandaloneConfigWriter())->write($this->configFile, ['provider' => 'anthropic', 'platform' => ['anthropic' => ['api_key' => '%env(ANTHROPIC_API_KEY)%']], 'model' => 'claude-opus-4-8']);

        self::assertStringEqualsFile($this->configFile, "provider: anthropic\nplatform:\n    anthropic: { api_key: '%env(ANTHROPIC_API_KEY)%' }\nmodel: claude-opus-4-8\n");
    }

    /**
     * @throws StandaloneConfigWriteException
     * @throws UnsafeStandaloneConfigWriteException
     */
    public function test_it_keeps_the_settings_of_an_existing_configuration_that_it_is_not_given(): void
    {
        (new Filesystem())->dumpFile($this->configFile, "provider: anthropic\nplatform:\n    anthropic: { api_key: '%env(ANTHROPIC_API_KEY)%' }\nmodel: old-model\nprivacy:\n    offline_only: true\naudit:\n    budget:\n        max_cost_usd: 5.0\n    custom_skills: []\nscan:\n    secret_scrubbing:\n        additional_patterns: ['acme_[a-z0-9]{32}']\ncache:\n    enabled: true\nhttp_timeout: 900\n");

        (new YamlStandaloneConfigWriter())->write($this->configFile, ['provider' => 'openai', 'platform' => ['openai' => ['api_key' => '%env(OPENAI_API_KEY)%']], 'model' => 'gpt-5.4']);

        self::assertSame(
            [
                'provider' => 'openai',
                'platform' => ['openai' => ['api_key' => '%env(OPENAI_API_KEY)%']],
                'model' => 'gpt-5.4',
                'privacy' => ['offline_only' => true],
                'audit' => ['budget' => ['max_cost_usd' => 5.0], 'custom_skills' => []],
                'scan' => ['secret_scrubbing' => ['additional_patterns' => ['acme_[a-z0-9]{32}']]],
                'cache' => ['enabled' => true],
                'http_timeout' => 900,
            ],
            Yaml::parseFile($this->configFile),
        );
    }

    /**
     * @throws StandaloneConfigWriteException
     * @throws UnsafeStandaloneConfigWriteException
     */
    public function test_it_replaces_a_whole_section_it_is_given_rather_than_merging_into_it(): void
    {
        (new Filesystem())->dumpFile($this->configFile, "platform:\n    anthropic: { api_key: '%env(ANTHROPIC_API_KEY)%' }\n    openai: { api_key: '%env(OPENAI_API_KEY)%' }\n");

        (new YamlStandaloneConfigWriter())->write($this->configFile, ['platform' => ['ollama' => ['endpoint' => 'http://localhost:11434']]]);

        self::assertSame(['platform' => ['ollama' => ['endpoint' => 'http://localhost:11434']]], Yaml::parseFile($this->configFile));
    }

    /**
     * @throws StandaloneConfigWriteException
     * @throws UnsafeStandaloneConfigWriteException
     */
    public function test_it_replaces_an_existing_file_that_is_not_valid_yaml(): void
    {
        (new Filesystem())->dumpFile($this->configFile, "model: [unclosed\n  - : :\n");

        (new YamlStandaloneConfigWriter())->write($this->configFile, ['model' => 'claude-opus-4-8']);

        self::assertSame(['model' => 'claude-opus-4-8'], Yaml::parseFile($this->configFile));
    }

    /**
     * @throws StandaloneConfigWriteException
     * @throws UnsafeStandaloneConfigWriteException
     */
    public function test_it_replaces_an_existing_file_holding_more_values_than_any_configuration_needs(): void
    {
        (new Filesystem())->dumpFile($this->configFile, "model: old-model\nnoise: [".implode(', ', range(1, StandaloneConfigFileReader::VALUE_LIMIT))."]\n");

        (new YamlStandaloneConfigWriter())->write($this->configFile, ['model' => 'claude-opus-4-8']);

        self::assertSame(['model' => 'claude-opus-4-8'], Yaml::parseFile($this->configFile));
    }

    /**
     * @throws StandaloneConfigWriteException
     * @throws UnsafeStandaloneConfigWriteException
     */
    #[DataProvider('stringsYamlWouldReadAsSomethingElse')]
    public function test_every_string_it_writes_is_read_back_as_the_same_string(string $value): void
    {
        $config = ['provider' => $value, 'platform' => ['generic' => ['default' => ['base_url' => $value]]], 'model' => $value];

        (new YamlStandaloneConfigWriter())->write($this->configFile, $config);

        self::assertSame($config, Yaml::parseFile($this->configFile));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function stringsYamlWouldReadAsSomethingElse(): iterable
    {
        yield 'infinity' => ['.inf'];
        yield 'capitalised infinity' => ['.Inf'];
        yield 'negative infinity' => ['-.inf'];
        yield 'not a number' => ['.nan'];
        yield 'capitalised not a number' => ['.NaN'];
        yield 'a float with digit separators' => ['1_000.5'];
        yield 'an exponent' => ['1e3'];
        yield 'a hexadecimal number' => ['0x1F'];
        yield 'an integer' => ['42'];
        yield 'a tilde' => ['~'];
        yield 'null' => ['null'];
        yield 'a boolean' => ['true'];
        yield 'a date' => ['2026-09-30'];
        yield 'an empty string' => [''];
    }

    /**
     * @throws StandaloneConfigWriteException
     * @throws UnsafeStandaloneConfigWriteException
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
     * @throws UnsafeStandaloneConfigWriteException
     */
    public function test_it_tightens_permissions_on_a_pre_existing_loosely_permissioned_config_file(): void
    {
        $filesystem = new Filesystem();
        $filesystem->mkdir(\dirname($this->configFile));
        $filesystem->dumpFile($this->configFile, "old: value\n");
        $filesystem->chmod($this->configFile, 0o644);

        (new YamlStandaloneConfigWriter($filesystem))->write($this->configFile, ['model' => 'claude-opus-4-8']);

        $permissions = fileperms($this->configFile);
        self::assertNotFalse($permissions);
        self::assertSame('0600', substr(\sprintf('%o', $permissions), -4));
    }

    /**
     * @throws StandaloneConfigWriteException
     * @throws UnsafeStandaloneConfigWriteException
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
     * @throws UnsafeStandaloneConfigWriteException
     */
    public function test_it_wraps_an_io_failure_as_a_standalone_config_write_exception(): void
    {
        $filesystem = new Filesystem();
        $blockingFile = \dirname($this->configFile).'/not-a-directory';
        $filesystem->mkdir(\dirname($blockingFile));
        $filesystem->dumpFile($blockingFile, 'x');

        $this->expectException(StandaloneConfigWriteException::class);
        $this->expectExceptionMessage('SYMFONY_SECURITY_AUDITOR_HOME');

        (new YamlStandaloneConfigWriter())->write($blockingFile.'/config.yaml', ['model' => 'claude-opus-4-8']);
    }

    /**
     * @throws StandaloneConfigWriteException
     * @throws UnsafeStandaloneConfigWriteException
     */
    public function test_it_refuses_to_write_through_a_symlinked_config_file(): void
    {
        $filesystem = new Filesystem();
        $outsideTarget = sys_get_temp_dir().'/ssa-write-target-'.bin2hex(random_bytes(6));
        $filesystem->dumpFile($outsideTarget, 'ORIGINAL');
        $filesystem->mkdir(\dirname($this->configFile));
        symlink($outsideTarget, $this->configFile);

        try {
            $this->expectException(UnsafeStandaloneConfigWriteException::class);

            (new YamlStandaloneConfigWriter($filesystem))->write($this->configFile, ['model' => 'claude-opus-4-8']);
        } finally {
            self::assertSame('ORIGINAL', file_get_contents($outsideTarget));
            $filesystem->remove($outsideTarget);
        }
    }

    /**
     * @throws StandaloneConfigWriteException
     * @throws UnsafeStandaloneConfigWriteException
     */
    public function test_it_refuses_to_write_through_a_symlinked_parent_directory(): void
    {
        $filesystem = new Filesystem();
        $outsideDir = sys_get_temp_dir().'/ssa-write-dir-'.bin2hex(random_bytes(6));
        $filesystem->mkdir($outsideDir);
        $filesystem->mkdir(\dirname($this->configFile, 2));
        symlink($outsideDir, \dirname($this->configFile));

        try {
            $this->expectException(UnsafeStandaloneConfigWriteException::class);

            (new YamlStandaloneConfigWriter($filesystem))->write($this->configFile, ['model' => 'claude-opus-4-8']);
        } finally {
            self::assertSame([], glob($outsideDir.'/*'));
            $filesystem->remove($outsideDir);
            $filesystem->remove(\dirname($this->configFile));
        }
    }
}
