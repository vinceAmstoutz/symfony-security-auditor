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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\MissingEnvironmentVariableException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\MissingPlatformException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnreadableCredentialFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandalonePlatformConfigResolver;

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
     */
    public function test_it_rejects_a_credential_file_that_cannot_be_read(): void
    {
        $missingFile = \sprintf('%s/absent-api-key', $this->tmpDir);

        $this->expectException(UnreadableCredentialFileException::class);
        $this->expectExceptionMessage(\sprintf('The credential file "%s", referenced by your config, could not be read.', $missingFile));

        (new StandalonePlatformConfigResolver(['ANTHROPIC_API_KEY_FILE' => $missingFile]))
            ->resolve(['platform' => ['anthropic' => ['api_key' => '%env(file:ANTHROPIC_API_KEY_FILE)%']]]);
    }

    /**
     * @throws MissingPlatformException
     * @throws MissingEnvironmentVariableException
     * @throws UnreadableCredentialFileException
     */
    public function test_it_rejects_a_credential_file_holding_only_whitespace(): void
    {
        $blankFile = $this->writeCredentialFile(" \n");

        $this->expectException(UnreadableCredentialFileException::class);
        $this->expectExceptionMessage(\sprintf('The credential file "%s", referenced by your config, is empty.', $blankFile));

        (new StandalonePlatformConfigResolver(['ANTHROPIC_API_KEY_FILE' => $blankFile]))
            ->resolve(['platform' => ['anthropic' => ['api_key' => '%env(file:ANTHROPIC_API_KEY_FILE)%']]]);
    }

    /**
     * @throws MissingPlatformException
     * @throws MissingEnvironmentVariableException
     * @throws UnreadableCredentialFileException
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

    private function writeCredentialFile(string $contents): string
    {
        $path = \sprintf('%s/api-key', $this->tmpDir);
        $this->filesystem->dumpFile($path, $contents);

        return $path;
    }
}
