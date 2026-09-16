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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\ConfiguredCredentialVariable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\XdgConfigPathResolver;

final class ConfiguredCredentialVariableTest extends TestCase
{
    private Filesystem $filesystem;

    private string $configHome;

    #[Override]
    protected function setUp(): void
    {
        $this->filesystem = new Filesystem();
        $this->configHome = sys_get_temp_dir().'/ssa-configured-variable-'.bin2hex(random_bytes(6));
    }

    #[Override]
    protected function tearDown(): void
    {
        $this->filesystem->remove($this->configHome);
    }

    public function test_it_names_the_variable_the_configuration_reads_the_key_from(): void
    {
        $this->writeConfig("platform:\n    anthropic:\n        api_key: '%env(ANTHROPIC_API_KEY)%'\n");

        self::assertSame('ANTHROPIC_API_KEY', $this->configuredCredentialVariable()->name());
    }

    public function test_it_names_the_variable_behind_a_credential_file(): void
    {
        $this->writeConfig("platform:\n    anthropic:\n        api_key: '%env(file:ANTHROPIC_API_KEY_FILE)%'\n");

        self::assertSame('ANTHROPIC_API_KEY_FILE', $this->configuredCredentialVariable()->name());
    }

    #[DataProvider('configurationsNamingNoVariable')]
    public function test_it_names_no_variable_when_the_configuration_points_at_none(string $config): void
    {
        $this->writeConfig($config);

        self::assertNull($this->configuredCredentialVariable()->name());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function configurationsNamingNoVariable(): iterable
    {
        yield 'a literal key' => ["platform:\n    anthropic:\n        api_key: 'anthropic-test-key-literal'\n"];
        yield 'a provider needing no key' => ["platform:\n    ollama:\n        host_url: 'http://localhost:11434'\n"];
        yield 'no platform block' => ["model: 'claude-opus-5'\n"];
        yield 'a platform block that is not a map' => ["platform: 'anthropic'\n"];
        yield 'unparsable yaml' => ["platform:\n  - [\n"];
        yield 'a document that is not a map' => ["- just\n- a list\n"];
    }

    public function test_it_names_no_variable_before_a_configuration_exists(): void
    {
        self::assertNull($this->configuredCredentialVariable()->name());
    }

    public function test_it_names_no_variable_when_no_configuration_directory_can_be_resolved(): void
    {
        self::assertNull((new ConfiguredCredentialVariable(new XdgConfigPathResolver(null, null, null)))->name());
    }

    private function writeConfig(string $contents): void
    {
        $this->filesystem->dumpFile($this->configHome.'/symfony-security-auditor/config.yaml', $contents);
    }

    private function configuredCredentialVariable(): ConfiguredCredentialVariable
    {
        return new ConfiguredCredentialVariable(new XdgConfigPathResolver($this->configHome, null, null));
    }
}
