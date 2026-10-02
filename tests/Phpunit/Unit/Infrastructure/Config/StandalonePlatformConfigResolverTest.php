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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Config;

use Override;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\CredentialStoreInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\MissingEnvironmentVariableException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\MissingPlatformException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnreadableCredentialFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnreadableCredentialStoreException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnsupportedEnvPlaceholderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandalonePlatformConfigResolver;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Config\Fixture\InMemoryCredentialStore;

final class StandalonePlatformConfigResolverTest extends TestCase
{
    private Filesystem $filesystem;

    private string $tmpDir;

    #[Override]
    protected function setUp(): void
    {
        $this->filesystem = new Filesystem();
        $this->tmpDir = sys_get_temp_dir().'/standalone_platform_config_resolver_test_'.uniqid('', true);
        $this->filesystem->mkdir($this->tmpDir);
    }

    #[Override]
    protected function tearDown(): void
    {
        $this->filesystem->remove($this->tmpDir);
    }

    /**
     * @throws MissingPlatformException
     * @throws MissingEnvironmentVariableException
     * @throws UnreadableCredentialFileException
     * @throws UnreadableCredentialStoreException
     * @throws UnsupportedEnvPlaceholderException
     */
    public function test_it_passes_the_platform_block_through_untouched(): void
    {
        $standalonePlatformConfig = (new StandalonePlatformConfigResolver())
            ->resolve(['platform' => ['anthropic' => ['api_key' => 'sk-literal']]]);

        self::assertSame(['platform' => ['anthropic' => ['api_key' => 'sk-literal']]], $standalonePlatformConfig->toAiConfig());
    }

    /**
     * @throws MissingPlatformException
     * @throws MissingEnvironmentVariableException
     * @throws UnreadableCredentialFileException
     * @throws UnreadableCredentialStoreException
     * @throws UnsupportedEnvPlaceholderException
     */
    public function test_it_resolves_env_placeholders_anywhere_in_the_platform_block(): void
    {
        $standalonePlatformConfig = (new StandalonePlatformConfigResolver(['ANTHROPIC_API_KEY' => 'sk-from-env']))
            ->resolve(['platform' => ['anthropic' => ['api_key' => '%env(ANTHROPIC_API_KEY)%']]]);

        self::assertSame(['platform' => ['anthropic' => ['api_key' => 'sk-from-env']]], $standalonePlatformConfig->toAiConfig());
    }

    /**
     * @throws MissingPlatformException
     * @throws MissingEnvironmentVariableException
     * @throws UnreadableCredentialFileException
     * @throws UnreadableCredentialStoreException
     * @throws UnsupportedEnvPlaceholderException
     */
    public function test_it_resolves_placeholders_in_a_nested_generic_platform(): void
    {
        $standalonePlatformConfig = (new StandalonePlatformConfigResolver(['LLM_BASE_URL' => 'http://localhost:1234']))
            ->resolve(['platform' => ['generic' => ['default' => ['base_url' => '%env(LLM_BASE_URL)%', 'supports_completions' => true]]]]);

        self::assertSame(
            ['platform' => ['generic' => ['default' => ['base_url' => 'http://localhost:1234', 'supports_completions' => true]]]],
            $standalonePlatformConfig->toAiConfig(),
        );
    }

    /**
     * @throws MissingPlatformException
     * @throws MissingEnvironmentVariableException
     * @throws UnreadableCredentialFileException
     * @throws UnreadableCredentialStoreException
     * @throws UnsupportedEnvPlaceholderException
     */
    public function test_a_run_that_needs_no_credential_substitutes_an_unusable_stand_in(): void
    {
        $standalonePlatformConfig = (new StandalonePlatformConfigResolver())
            ->resolve(['platform' => ['anthropic' => ['api_key' => '%env(ANTHROPIC_API_KEY)%']]], false);

        self::assertSame(
            ['platform' => ['anthropic' => ['api_key' => StandalonePlatformConfigResolver::UNNEEDED_CREDENTIAL]]],
            $standalonePlatformConfig->toAiConfig(),
        );
    }

    /**
     * @throws MissingPlatformException
     * @throws MissingEnvironmentVariableException
     * @throws UnreadableCredentialFileException
     * @throws UnreadableCredentialStoreException
     * @throws UnsupportedEnvPlaceholderException
     */
    public function test_a_run_that_needs_no_credential_still_prefers_the_real_one_when_it_is_set(): void
    {
        $standalonePlatformConfig = (new StandalonePlatformConfigResolver(['ANTHROPIC_API_KEY' => 'sk-from-env']))
            ->resolve(['platform' => ['anthropic' => ['api_key' => '%env(ANTHROPIC_API_KEY)%']]], false);

        self::assertSame(['platform' => ['anthropic' => ['api_key' => 'sk-from-env']]], $standalonePlatformConfig->toAiConfig());
    }

    /**
     * @throws MissingPlatformException
     * @throws MissingEnvironmentVariableException
     * @throws UnreadableCredentialFileException
     * @throws UnreadableCredentialStoreException
     * @throws UnsupportedEnvPlaceholderException
     */
    public function test_it_carries_the_active_provider_selector(): void
    {
        $standalonePlatformConfig = (new StandalonePlatformConfigResolver())->resolve([
            'provider' => 'openai',
            'platform' => ['anthropic' => ['api_key' => 'a'], 'openai' => ['api_key' => 'b']],
        ]);

        self::assertSame('openai', $standalonePlatformConfig->activeProvider);
    }

    /**
     * @throws MissingPlatformException
     * @throws MissingEnvironmentVariableException
     * @throws UnreadableCredentialFileException
     * @throws UnreadableCredentialStoreException
     * @throws UnsupportedEnvPlaceholderException
     */
    public function test_it_has_no_active_provider_when_the_selector_is_absent(): void
    {
        $standalonePlatformConfig = (new StandalonePlatformConfigResolver())
            ->resolve(['platform' => ['anthropic' => ['api_key' => 'a']]]);

        self::assertNull($standalonePlatformConfig->activeProvider);
    }

    /**
     * @throws MissingPlatformException
     * @throws MissingEnvironmentVariableException
     * @throws UnreadableCredentialFileException
     * @throws UnreadableCredentialStoreException
     * @throws UnsupportedEnvPlaceholderException
     */
    public function test_it_ignores_an_empty_active_provider_selector(): void
    {
        $standalonePlatformConfig = (new StandalonePlatformConfigResolver())
            ->resolve(['provider' => '', 'platform' => ['anthropic' => ['api_key' => 'a']]]);

        self::assertNull($standalonePlatformConfig->activeProvider);
    }

    /**
     * @throws MissingPlatformException
     * @throws MissingEnvironmentVariableException
     * @throws UnreadableCredentialFileException
     * @throws UnreadableCredentialStoreException
     * @throws UnsupportedEnvPlaceholderException
     */
    public function test_it_rejects_a_config_without_a_platform_block(): void
    {
        $this->expectException(MissingPlatformException::class);

        (new StandalonePlatformConfigResolver())->resolve(['provider' => 'anthropic']);
    }

    /**
     * @throws MissingPlatformException
     * @throws MissingEnvironmentVariableException
     * @throws UnreadableCredentialFileException
     * @throws UnreadableCredentialStoreException
     * @throws UnsupportedEnvPlaceholderException
     */
    public function test_it_rejects_an_empty_platform_block(): void
    {
        $this->expectException(MissingPlatformException::class);

        (new StandalonePlatformConfigResolver())->resolve(['platform' => []]);
    }

    /**
     * @throws MissingPlatformException
     * @throws MissingEnvironmentVariableException
     * @throws UnreadableCredentialFileException
     * @throws UnreadableCredentialStoreException
     * @throws UnsupportedEnvPlaceholderException
     */
    public function test_it_rejects_an_env_placeholder_whose_variable_is_unset(): void
    {
        $this->expectException(MissingEnvironmentVariableException::class);
        $this->expectExceptionMessage('"ANTHROPIC_API_KEY"');

        (new StandalonePlatformConfigResolver())
            ->resolve(['platform' => ['anthropic' => ['api_key' => '%env(ANTHROPIC_API_KEY)%']]]);
    }

    /**
     * @throws MissingPlatformException
     * @throws MissingEnvironmentVariableException
     * @throws UnreadableCredentialFileException
     * @throws UnreadableCredentialStoreException
     * @throws UnsupportedEnvPlaceholderException
     */
    public function test_it_rejects_a_mixed_case_env_placeholder_instead_of_passing_it_through_as_a_literal(): void
    {
        $this->expectException(MissingEnvironmentVariableException::class);
        $this->expectExceptionMessage('"openaiApiKey"');

        (new StandalonePlatformConfigResolver())
            ->resolve(['platform' => ['openai' => ['api_key' => '%env(openaiApiKey)%']]]);
    }

    /**
     * @throws MissingPlatformException
     * @throws MissingEnvironmentVariableException
     * @throws UnreadableCredentialFileException
     * @throws UnreadableCredentialStoreException
     * @throws UnsupportedEnvPlaceholderException
     */
    #[DataProvider('credentialFileContents')]
    public function test_it_reads_the_credential_from_the_file_its_variable_points_at(string $contents): void
    {
        $credentialFile = $this->writeCredentialFile($contents);

        $standalonePlatformConfig = (new StandalonePlatformConfigResolver(['ANTHROPIC_API_KEY_FILE' => $credentialFile]))
            ->resolve(['platform' => ['anthropic' => ['api_key' => '%env(file:ANTHROPIC_API_KEY_FILE)%']]]);

        self::assertSame(['platform' => ['anthropic' => ['api_key' => 'sk-from-file']]], $standalonePlatformConfig->toAiConfig());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function credentialFileContents(): iterable
    {
        yield 'bare value' => ['sk-from-file'];
        yield 'trailing newline' => ["sk-from-file\n"];
        yield 'windows line ending' => ["sk-from-file\r\n"];
        yield 'surrounding whitespace' => ["  sk-from-file \n"];
    }

    /**
     * @throws MissingPlatformException
     * @throws MissingEnvironmentVariableException
     * @throws UnreadableCredentialFileException
     * @throws UnreadableCredentialStoreException
     * @throws UnsupportedEnvPlaceholderException
     */
    public function test_it_rejects_a_file_placeholder_whose_variable_is_unset(): void
    {
        $this->expectException(MissingEnvironmentVariableException::class);
        $this->expectExceptionMessage('"ANTHROPIC_API_KEY_FILE"');

        (new StandalonePlatformConfigResolver())
            ->resolve(['platform' => ['anthropic' => ['api_key' => '%env(file:ANTHROPIC_API_KEY_FILE)%']]]);
    }

    /**
     * @throws MissingPlatformException
     * @throws MissingEnvironmentVariableException
     * @throws UnreadableCredentialFileException
     * @throws UnreadableCredentialStoreException
     * @throws UnsupportedEnvPlaceholderException
     */
    public function test_it_rejects_a_credential_file_that_cannot_be_read(): void
    {
        $missingFile = \sprintf('%s/absent-api-key', $this->tmpDir);

        $this->expectException(UnreadableCredentialFileException::class);
        $this->expectExceptionMessage('The credential file your config reads through "ANTHROPIC_API_KEY_FILE" could not be read');

        (new StandalonePlatformConfigResolver(['ANTHROPIC_API_KEY_FILE' => $missingFile]))
            ->resolve(['platform' => ['anthropic' => ['api_key' => '%env(file:ANTHROPIC_API_KEY_FILE)%']]]);
    }

    /**
     * @throws MissingPlatformException
     * @throws MissingEnvironmentVariableException
     * @throws UnreadableCredentialFileException
     * @throws UnreadableCredentialStoreException
     * @throws UnsupportedEnvPlaceholderException
     */
    public function test_it_rejects_a_credential_file_holding_only_whitespace(): void
    {
        $blankFile = $this->writeCredentialFile(" \n");

        $this->expectException(UnreadableCredentialFileException::class);
        $this->expectExceptionMessage('The credential file your config reads through "ANTHROPIC_API_KEY_FILE" is empty');

        (new StandalonePlatformConfigResolver(['ANTHROPIC_API_KEY_FILE' => $blankFile]))
            ->resolve(['platform' => ['anthropic' => ['api_key' => '%env(file:ANTHROPIC_API_KEY_FILE)%']]]);
    }

    /**
     * @throws MissingPlatformException
     * @throws MissingEnvironmentVariableException
     * @throws UnreadableCredentialFileException
     * @throws UnreadableCredentialStoreException
     * @throws UnsupportedEnvPlaceholderException
     */
    public function test_a_run_that_needs_no_credential_tolerates_an_unset_file_variable(): void
    {
        $standalonePlatformConfig = (new StandalonePlatformConfigResolver())
            ->resolve(['platform' => ['anthropic' => ['api_key' => '%env(file:ANTHROPIC_API_KEY_FILE)%']]], false);

        self::assertSame(
            ['platform' => ['anthropic' => ['api_key' => StandalonePlatformConfigResolver::UNNEEDED_CREDENTIAL]]],
            $standalonePlatformConfig->toAiConfig(),
        );
    }

    /**
     * @throws MissingPlatformException
     * @throws MissingEnvironmentVariableException
     * @throws UnreadableCredentialFileException
     * @throws UnreadableCredentialStoreException
     * @throws UnsupportedEnvPlaceholderException
     */
    public function test_a_run_that_needs_no_credential_tolerates_an_unreadable_credential_file(): void
    {
        $standalonePlatformConfig = (new StandalonePlatformConfigResolver(['ANTHROPIC_API_KEY_FILE' => \sprintf('%s/absent-api-key', $this->tmpDir)]))
            ->resolve(['platform' => ['anthropic' => ['api_key' => '%env(file:ANTHROPIC_API_KEY_FILE)%']]], false);

        self::assertSame(
            ['platform' => ['anthropic' => ['api_key' => StandalonePlatformConfigResolver::UNNEEDED_CREDENTIAL]]],
            $standalonePlatformConfig->toAiConfig(),
        );
    }

    /**
     * @throws MissingPlatformException
     * @throws MissingEnvironmentVariableException
     * @throws UnreadableCredentialFileException
     * @throws UnreadableCredentialStoreException
     * @throws UnsupportedEnvPlaceholderException
     */
    public function test_a_run_that_needs_no_credential_tolerates_a_blank_credential_file(): void
    {
        $standalonePlatformConfig = (new StandalonePlatformConfigResolver(['ANTHROPIC_API_KEY_FILE' => $this->writeCredentialFile('')]))
            ->resolve(['platform' => ['anthropic' => ['api_key' => '%env(file:ANTHROPIC_API_KEY_FILE)%']]], false);

        self::assertSame(
            ['platform' => ['anthropic' => ['api_key' => StandalonePlatformConfigResolver::UNNEEDED_CREDENTIAL]]],
            $standalonePlatformConfig->toAiConfig(),
        );
    }

    /**
     * @throws MissingPlatformException
     * @throws MissingEnvironmentVariableException
     * @throws UnreadableCredentialFileException
     * @throws UnreadableCredentialStoreException
     * @throws UnsupportedEnvPlaceholderException
     */
    #[DataProvider('credentialSources')]
    public function test_it_escapes_a_resolved_credential_so_the_container_reads_it_literally(string $placeholder, bool $fromFile, bool $fromStore): void
    {
        $credential = 'sk-%kernel.secret%-50%%';
        $environment = match (true) {
            $fromFile => ['ANTHROPIC_API_KEY_FILE' => $this->writeCredentialFile($credential)],
            $fromStore => [],
            default => ['ANTHROPIC_API_KEY' => $credential],
        };

        $standalonePlatformConfig = (new StandalonePlatformConfigResolver($environment, credentialStore: new InMemoryCredentialStore($fromStore ? ['ANTHROPIC_API_KEY' => $credential] : [])))
            ->resolve(['platform' => ['anthropic' => ['api_key' => $placeholder]]]);

        self::assertSame(['platform' => ['anthropic' => ['api_key' => 'sk-%%kernel.secret%%-50%%%%']]], $standalonePlatformConfig->toAiConfig());
    }

    /**
     * @return iterable<string, array{string, bool, bool}>
     */
    public static function credentialSources(): iterable
    {
        yield 'an exported variable' => ['%env(ANTHROPIC_API_KEY)%', false, false];
        yield 'a credential file' => ['%env(file:ANTHROPIC_API_KEY_FILE)%', true, false];
        yield 'the credential store' => ['%env(ANTHROPIC_API_KEY)%', false, true];
    }

    /**
     * @throws MissingPlatformException
     * @throws MissingEnvironmentVariableException
     * @throws UnreadableCredentialFileException
     * @throws UnreadableCredentialStoreException
     * @throws UnsupportedEnvPlaceholderException
     */
    public function test_it_leaves_a_literal_written_in_the_configuration_as_written(): void
    {
        $standalonePlatformConfig = (new StandalonePlatformConfigResolver())
            ->resolve(['platform' => ['anthropic' => ['api_key' => 'sk-50%%']]]);

        self::assertSame(['platform' => ['anthropic' => ['api_key' => 'sk-50%%']]], $standalonePlatformConfig->toAiConfig());
    }

    private function writeCredentialFile(string $contents): string
    {
        $path = \sprintf('%s/api-key', $this->tmpDir);
        $this->filesystem->dumpFile($path, $contents);

        return $path;
    }

    /**
     * @throws MissingPlatformException
     * @throws MissingEnvironmentVariableException
     * @throws UnreadableCredentialFileException
     * @throws UnreadableCredentialStoreException
     * @throws UnsupportedEnvPlaceholderException
     */
    public function test_it_falls_back_to_the_stored_credential_when_the_variable_is_unset(): void
    {
        $standalonePlatformConfig = (new StandalonePlatformConfigResolver([], credentialStore: new InMemoryCredentialStore(['ANTHROPIC_API_KEY' => 'sk-from-the-store'])))
            ->resolve(['platform' => ['anthropic' => ['api_key' => '%env(ANTHROPIC_API_KEY)%']]]);

        self::assertSame(['platform' => ['anthropic' => ['api_key' => 'sk-from-the-store']]], $standalonePlatformConfig->toAiConfig());
    }

    /**
     * @throws MissingPlatformException
     * @throws MissingEnvironmentVariableException
     * @throws UnreadableCredentialFileException
     * @throws UnreadableCredentialStoreException
     * @throws UnsupportedEnvPlaceholderException
     */
    public function test_it_lets_an_exported_variable_override_the_stored_credential(): void
    {
        $standalonePlatformConfig = (new StandalonePlatformConfigResolver(['ANTHROPIC_API_KEY' => 'sk-from-env'], credentialStore: new InMemoryCredentialStore(['ANTHROPIC_API_KEY' => 'sk-from-the-store'])))
            ->resolve(['platform' => ['anthropic' => ['api_key' => '%env(ANTHROPIC_API_KEY)%']]]);

        self::assertSame(['platform' => ['anthropic' => ['api_key' => 'sk-from-env']]], $standalonePlatformConfig->toAiConfig());
    }

    /**
     * @throws MissingPlatformException
     * @throws MissingEnvironmentVariableException
     * @throws UnreadableCredentialFileException
     * @throws UnreadableCredentialStoreException
     * @throws UnsupportedEnvPlaceholderException
     */
    public function test_it_falls_back_to_the_stored_credential_when_a_credential_file_is_not_configured(): void
    {
        $standalonePlatformConfig = (new StandalonePlatformConfigResolver([], credentialStore: new InMemoryCredentialStore(['ANTHROPIC_API_KEY_FILE' => 'sk-from-the-store'])))
            ->resolve(['platform' => ['anthropic' => ['api_key' => '%env(file:ANTHROPIC_API_KEY_FILE)%']]]);

        self::assertSame(['platform' => ['anthropic' => ['api_key' => 'sk-from-the-store']]], $standalonePlatformConfig->toAiConfig());
    }

    /**
     * @throws MissingEnvironmentVariableException
     * @throws MissingPlatformException
     * @throws UnreadableCredentialFileException
     * @throws UnreadableCredentialStoreException
     * @throws UnsupportedEnvPlaceholderException
     */
    public function test_it_reports_a_credential_that_is_neither_exported_nor_stored(): void
    {
        $this->expectException(MissingEnvironmentVariableException::class);
        $this->expectExceptionMessage('run "auth:set" to store the key on this machine');

        (new StandalonePlatformConfigResolver([], credentialStore: new InMemoryCredentialStore()))
            ->resolve(['platform' => ['anthropic' => ['api_key' => '%env(ANTHROPIC_API_KEY)%']]]);
    }

    /**
     * @throws MissingPlatformException
     * @throws MissingEnvironmentVariableException
     * @throws UnreadableCredentialStoreException
     * @throws UnsupportedEnvPlaceholderException
     */
    public function test_it_names_the_variable_rather_than_the_value_it_holds_when_the_credential_file_cannot_be_read(): void
    {
        $keyPastedWhereAPathBelongs = 'sk-ant-api03-pasted-where-a-path-belongs';

        try {
            (new StandalonePlatformConfigResolver(['ANTHROPIC_API_KEY_FILE' => $keyPastedWhereAPathBelongs]))
                ->resolve(['platform' => ['anthropic' => ['api_key' => '%env(file:ANTHROPIC_API_KEY_FILE)%']]]);
            self::fail('A credential file that does not exist must be refused.');
        } catch (UnreadableCredentialFileException $unreadableCredentialFileException) {
            self::assertStringContainsString('(ANTHROPIC_API_KEY_FILE holds "sk-ant…ongs")', $unreadableCredentialFileException->getMessage());
            self::assertStringNotContainsString($keyPastedWhereAPathBelongs, $unreadableCredentialFileException->getMessage());
        }
    }

    /**
     * @throws MissingPlatformException
     * @throws MissingEnvironmentVariableException
     * @throws UnreadableCredentialFileException
     * @throws UnreadableCredentialStoreException
     * @throws UnsupportedEnvPlaceholderException
     */
    public function test_it_reports_a_plain_setting_whose_variable_is_unset_without_speaking_of_the_api_key(): void
    {
        $this->expectException(MissingEnvironmentVariableException::class);
        $this->expectExceptionMessage('The environment variable "LLM_BASE_URL", referenced by your config, is not set.');

        (new StandalonePlatformConfigResolver(['LLM_API_KEY' => 'sk-from-env']))
            ->resolve(['platform' => ['generic' => ['default' => ['base_url' => '%env(LLM_BASE_URL)%', 'api_key' => '%env(LLM_API_KEY)%']]]]);
    }

    /**
     * @throws MissingPlatformException
     * @throws MissingEnvironmentVariableException
     * @throws UnreadableCredentialFileException
     * @throws UnreadableCredentialStoreException
     * @throws UnsupportedEnvPlaceholderException
     */
    public function test_a_platform_the_provider_does_not_select_needs_none_of_its_settings(): void
    {
        $standalonePlatformConfig = (new StandalonePlatformConfigResolver(['GW_TOKEN' => 'gw-secret']))->resolve([
            'provider' => 'generic.my_gateway',
            'platform' => [
                'openai' => ['api_key' => '%env(OPENAI_API_KEY)%'],
                'generic' => ['my_gateway' => ['base_url' => 'https://gw.example', 'api_key' => '%env(GW_TOKEN)%']],
                'ollama' => ['endpoint' => '%env(OLLAMA_URL)%'],
            ],
        ]);

        self::assertSame(
            ['platform' => [
                'openai' => ['api_key' => StandalonePlatformConfigResolver::UNNEEDED_CREDENTIAL],
                'generic' => ['my_gateway' => ['base_url' => 'https://gw.example', 'api_key' => 'gw-secret']],
                'ollama' => ['endpoint' => StandalonePlatformConfigResolver::UNNEEDED_CREDENTIAL],
            ]],
            $standalonePlatformConfig->toAiConfig(),
        );
    }

    /**
     * @throws MissingPlatformException
     * @throws MissingEnvironmentVariableException
     * @throws UnreadableCredentialFileException
     * @throws UnreadableCredentialStoreException
     * @throws UnsupportedEnvPlaceholderException
     */
    public function test_an_instance_the_provider_does_not_select_needs_none_of_its_settings(): void
    {
        $standalonePlatformConfig = (new StandalonePlatformConfigResolver(['TOKEN_B' => 'secret-b']))->resolve([
            'provider' => 'generic.b',
            'platform' => ['generic' => [
                'a' => ['base_url' => '%env(URL_A)%', 'api_key' => '%env(TOKEN_A)%'],
                'b' => ['base_url' => 'https://b.example', 'api_key' => '%env(TOKEN_B)%'],
            ]],
        ]);

        self::assertSame(
            ['platform' => ['generic' => [
                'a' => ['base_url' => StandalonePlatformConfigResolver::UNNEEDED_CREDENTIAL, 'api_key' => StandalonePlatformConfigResolver::UNNEEDED_CREDENTIAL],
                'b' => ['base_url' => 'https://b.example', 'api_key' => 'secret-b'],
            ]]],
            $standalonePlatformConfig->toAiConfig(),
        );
    }

    /**
     * @param array<array-key, mixed> $platform
     *
     * @throws MissingPlatformException
     * @throws MissingEnvironmentVariableException
     * @throws UnreadableCredentialFileException
     * @throws UnreadableCredentialStoreException
     * @throws UnsupportedEnvPlaceholderException
     */
    #[DataProvider('selectedConnectionsMissingTheirKey')]
    public function test_the_key_of_the_connection_the_provider_selects_is_still_required(string $provider, array $platform, string $expectedVariable): void
    {
        $this->expectException(MissingEnvironmentVariableException::class);
        $this->expectExceptionMessage(\sprintf('"%s"', $expectedVariable));

        (new StandalonePlatformConfigResolver(['ANTHROPIC_API_KEY' => 'sk-anthropic', 'TOKEN_A' => 'secret-a']))->resolve(['provider' => $provider, 'platform' => $platform]);
    }

    /**
     * @return iterable<string, array{string, array<array-key, mixed>, string}>
     */
    public static function selectedConnectionsMissingTheirKey(): iterable
    {
        yield 'a flat platform' => ['openai', ['anthropic' => ['api_key' => '%env(ANTHROPIC_API_KEY)%'], 'openai' => ['api_key' => '%env(OPENAI_API_KEY)%']], 'OPENAI_API_KEY'];
        yield 'an instance' => ['generic.b', ['generic' => ['a' => ['api_key' => '%env(TOKEN_A)%'], 'b' => ['api_key' => '%env(TOKEN_B)%']]], 'TOKEN_B'];
        yield 'an instance named by a number' => ['generic.7', ['generic' => [7 => ['api_key' => '%env(TOKEN_7)%']]], 'TOKEN_7'];
    }

    /**
     * @param array<array-key, mixed> $platform
     * @param array<array-key, mixed> $expected
     *
     * @throws MissingPlatformException
     * @throws MissingEnvironmentVariableException
     * @throws UnreadableCredentialFileException
     * @throws UnreadableCredentialStoreException
     * @throws UnsupportedEnvPlaceholderException
     */
    #[DataProvider('providersSelectingNoConnection')]
    public function test_a_provider_selecting_no_connection_requires_no_key(string $provider, array $platform, array $expected): void
    {
        self::assertSame($expected, (new StandalonePlatformConfigResolver())->resolve(['provider' => $provider, 'platform' => $platform])->platform);
    }

    /**
     * @return iterable<string, array{string, array<array-key, mixed>, array<array-key, mixed>}>
     */
    public static function providersSelectingNoConnection(): iterable
    {
        yield 'an instance of a platform whose block holds none' => [
            'anthropic.prod',
            ['anthropic' => ['api_key' => '%env(ANTHROPIC_API_KEY)%']],
            ['anthropic' => ['api_key' => StandalonePlatformConfigResolver::UNNEEDED_CREDENTIAL]],
        ];
        yield 'an instance of a platform whose block is not a map' => [
            'generic.gw',
            ['generic' => '%env(GENERIC_BLOCK)%'],
            ['generic' => StandalonePlatformConfigResolver::UNNEEDED_CREDENTIAL],
        ];
    }

    /**
     * @throws MissingPlatformException
     * @throws MissingEnvironmentVariableException
     * @throws UnreadableCredentialFileException
     * @throws UnreadableCredentialStoreException
     * @throws UnsupportedEnvPlaceholderException
     */
    public function test_a_platform_the_provider_does_not_select_is_never_looked_up_in_the_credential_store(): void
    {
        $credentialStore = $this->createMock(CredentialStoreInterface::class);
        $credentialStore->expects(self::once())->method('read')->with('GW_TOKEN')->willReturn('gw-stored');

        $standalonePlatformConfig = (new StandalonePlatformConfigResolver([], credentialStore: $credentialStore))->resolve([
            'provider' => 'generic.my_gateway',
            'platform' => [
                'openai' => ['api_key' => '%env(OPENAI_API_KEY)%'],
                'generic' => ['my_gateway' => ['base_url' => 'https://gw.example', 'api_key' => '%env(GW_TOKEN)%']],
            ],
        ]);

        self::assertSame(
            ['openai' => ['api_key' => StandalonePlatformConfigResolver::UNNEEDED_CREDENTIAL], 'generic' => ['my_gateway' => ['base_url' => 'https://gw.example', 'api_key' => 'gw-stored']]],
            $standalonePlatformConfig->platform,
        );
    }

    /**
     * @throws MissingPlatformException
     * @throws MissingEnvironmentVariableException
     * @throws UnreadableCredentialFileException
     * @throws UnreadableCredentialStoreException
     * @throws UnsupportedEnvPlaceholderException
     */
    public function test_a_platform_the_provider_does_not_select_still_refuses_a_placeholder_no_run_could_resolve(): void
    {
        $this->expectException(UnsupportedEnvPlaceholderException::class);

        (new StandalonePlatformConfigResolver(['GW_TOKEN' => 'gw-secret']))->resolve([
            'provider' => 'generic.my_gateway',
            'platform' => [
                'openai' => ['api_key' => '%env(trim:OPENAI_API_KEY)%'],
                'generic' => ['my_gateway' => ['base_url' => 'https://gw.example', 'api_key' => '%env(GW_TOKEN)%']],
            ],
        ]);
    }

    /**
     * @throws MissingPlatformException
     * @throws MissingEnvironmentVariableException
     * @throws UnreadableCredentialFileException
     * @throws UnreadableCredentialStoreException
     * @throws UnsupportedEnvPlaceholderException
     */
    public function test_a_run_that_needs_no_credential_needs_none_from_the_selected_platform_either(): void
    {
        $standalonePlatformConfig = (new StandalonePlatformConfigResolver())->resolve(
            ['provider' => 'openai', 'platform' => ['openai' => ['api_key' => '%env(OPENAI_API_KEY)%']]],
            false,
        );

        self::assertSame(['platform' => ['openai' => ['api_key' => StandalonePlatformConfigResolver::UNNEEDED_CREDENTIAL]]], $standalonePlatformConfig->toAiConfig());
    }

    /**
     * @throws MissingPlatformException
     * @throws MissingEnvironmentVariableException
     * @throws UnreadableCredentialFileException
     * @throws UnreadableCredentialStoreException
     * @throws UnsupportedEnvPlaceholderException
     */
    public function test_a_run_that_needs_no_credential_never_opens_the_credential_store(): void
    {
        $credentialStore = $this->createMock(CredentialStoreInterface::class);
        $credentialStore->expects(self::never())->method('read');

        $standalonePlatformConfig = (new StandalonePlatformConfigResolver([], credentialStore: $credentialStore))
            ->resolve(['platform' => ['anthropic' => ['api_key' => '%env(ANTHROPIC_API_KEY)%']]], false);

        self::assertSame(
            ['platform' => ['anthropic' => ['api_key' => StandalonePlatformConfigResolver::UNNEEDED_CREDENTIAL]]],
            $standalonePlatformConfig->toAiConfig(),
        );
    }

    /**
     * @throws MissingPlatformException
     * @throws MissingEnvironmentVariableException
     * @throws UnreadableCredentialFileException
     * @throws UnreadableCredentialStoreException
     * @throws UnsupportedEnvPlaceholderException
     */
    public function test_it_never_reads_a_plain_setting_from_the_credential_store(): void
    {
        $this->expectException(MissingEnvironmentVariableException::class);
        $this->expectExceptionMessage('"LLM_BASE_URL"');

        (new StandalonePlatformConfigResolver([], credentialStore: new InMemoryCredentialStore(['LLM_BASE_URL' => 'http://stored.example'])))
            ->resolve(['platform' => ['generic' => ['default' => ['base_url' => '%env(LLM_BASE_URL)%']]]]);
    }

    /**
     * @throws MissingPlatformException
     * @throws MissingEnvironmentVariableException
     * @throws UnreadableCredentialFileException
     * @throws UnreadableCredentialStoreException
     * @throws UnsupportedEnvPlaceholderException
     */
    public function test_it_reads_a_plain_setting_from_a_file_its_variable_points_at(): void
    {
        $baseUrlFile = $this->writeCredentialFile("http://gateway.example\n");

        $standalonePlatformConfig = (new StandalonePlatformConfigResolver(['LLM_BASE_URL_FILE' => $baseUrlFile]))
            ->resolve(['platform' => ['generic' => ['default' => ['base_url' => '%env(file:LLM_BASE_URL_FILE)%']]]]);

        self::assertSame(['platform' => ['generic' => ['default' => ['base_url' => 'http://gateway.example']]]], $standalonePlatformConfig->toAiConfig());
    }

    /**
     * @throws MissingPlatformException
     * @throws MissingEnvironmentVariableException
     * @throws UnreadableCredentialFileException
     * @throws UnreadableCredentialStoreException
     * @throws UnsupportedEnvPlaceholderException
     */
    public function test_a_run_that_needs_no_credential_tolerates_an_unset_plain_setting(): void
    {
        $standalonePlatformConfig = (new StandalonePlatformConfigResolver())
            ->resolve(['platform' => ['generic' => ['default' => ['base_url' => '%env(LLM_BASE_URL)%']]]], false);

        self::assertSame(
            ['platform' => ['generic' => ['default' => ['base_url' => StandalonePlatformConfigResolver::UNNEEDED_CREDENTIAL]]]],
            $standalonePlatformConfig->toAiConfig(),
        );
    }

    /**
     * @throws MissingPlatformException
     * @throws MissingEnvironmentVariableException
     * @throws UnreadableCredentialFileException
     * @throws UnreadableCredentialStoreException
     * @throws UnsupportedEnvPlaceholderException
     */
    #[DataProvider('placeholdersItCannotResolve')]
    public function test_it_refuses_a_placeholder_it_cannot_resolve_rather_than_asking_for_a_variable_nobody_can_export(string $placeholder, bool $credentialsRequired): void
    {
        $this->expectException(UnsupportedEnvPlaceholderException::class);

        (new StandalonePlatformConfigResolver(['API_KEY' => 'sk-from-env']))
            ->resolve(['platform' => ['anthropic' => ['api_key' => $placeholder]]], $credentialsRequired);
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function placeholdersItCannotResolve(): iterable
    {
        yield 'the trim processor' => ['%env(trim:API_KEY)%', true];
        yield 'the string processor' => ['%env(string:API_KEY)%', true];
        yield 'the default processor' => ['%env(default::API_KEY)%', true];
        yield 'a processor chained after file' => ['%env(file:trim:API_KEY)%', true];
        yield 'a name no shell can export' => ['%env(API-KEY)%', true];
        yield 'a file placeholder naming no variable' => ['%env(file:)%', true];
        yield 'a processor in a run that needs no credential' => ['%env(trim:API_KEY)%', false];
    }

    /**
     * @throws MissingPlatformException
     * @throws MissingEnvironmentVariableException
     * @throws UnreadableCredentialFileException
     * @throws UnreadableCredentialStoreException
     * @throws UnsupportedEnvPlaceholderException
     */
    public function test_it_names_the_spellings_it_supports_when_refusing_a_placeholder(): void
    {
        $this->expectExceptionMessage('The placeholder "%env(trim:API_KEY)%" applies an env processor, and the standalone binary applies none (trim:, string:, default:, …): it reads only "%env(VAR)%" and "%env(file:VAR)%"');

        (new StandalonePlatformConfigResolver(['API_KEY' => 'sk-from-env']))
            ->resolve(['platform' => ['generic' => ['default' => ['base_url' => '%env(trim:API_KEY)%']]]]);
    }

    /**
     * @throws MissingPlatformException
     * @throws MissingEnvironmentVariableException
     * @throws UnreadableCredentialFileException
     * @throws UnreadableCredentialStoreException
     * @throws UnsupportedEnvPlaceholderException
     */
    public function test_it_quotes_a_long_refused_placeholder_in_full_so_the_line_can_be_found(): void
    {
        $this->expectExceptionMessage('The placeholder "%env(default::ANTHROPIC_API_KEY)%"');

        (new StandalonePlatformConfigResolver())
            ->resolve(['platform' => ['anthropic' => ['api_key' => '%env(default::ANTHROPIC_API_KEY)%']]]);
    }

    /**
     * @throws MissingPlatformException
     * @throws MissingEnvironmentVariableException
     * @throws UnreadableCredentialFileException
     * @throws UnreadableCredentialStoreException
     */
    public function test_a_key_pasted_as_the_placeholder_name_is_never_echoed_in_the_refusal(): void
    {
        $pastedKey = 'sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789';

        $caught = null;
        try {
            (new StandalonePlatformConfigResolver())->resolve(['platform' => ['anthropic' => ['api_key' => '%env('.$pastedKey.')%']]]);
        } catch (UnsupportedEnvPlaceholderException $unsupportedEnvPlaceholderException) {
            $caught = $unsupportedEnvPlaceholderException;
        }

        self::assertInstanceOf(UnsupportedEnvPlaceholderException::class, $caught);
        self::assertStringNotContainsString($pastedKey, $caught->getMessage());
    }
}
