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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\EndToEnd;

use Ergebnis\PHPUnit\SlowTestDetector\Attribute\MaximumDuration;
use Override;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Command\LazyCommand;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\MissingEnvironmentVariableException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Mcp\McpServeCommand;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\StandaloneApplicationFactory;

final class StandaloneMcpServeEndToEndTest extends TestCase
{
    private Filesystem $filesystem;

    private string $configHome;

    private string $cacheHome;

    #[Override]
    protected function setUp(): void
    {
        $this->filesystem = new Filesystem();
        $suffix = bin2hex(random_bytes(6));
        $this->configHome = sys_get_temp_dir().'/ssa-mcp-config-'.$suffix;
        $this->cacheHome = sys_get_temp_dir().'/ssa-mcp-cache-'.$suffix;
    }

    #[Override]
    protected function tearDown(): void
    {
        $this->filesystem->remove([$this->configHome, $this->cacheHome]);
    }

    #[RunInSeparateProcess]
    #[MaximumDuration(4000)]
    public function test_the_binary_builds_the_mcp_server_from_the_user_configuration(): void
    {
        $this->writeConfig("platform:\n  generic:\n    default:\n      base_url: 'http://localhost'\nmodel: 'gpt-4'\n");

        self::assertSame(McpServeCommand::NAME, $this->resolvedMcpServeCommand()->getCommand()->getName());
    }

    #[RunInSeparateProcess]
    #[MaximumDuration(4000)]
    public function test_the_mcp_server_refuses_to_start_without_a_provider_credential(): void
    {
        $this->writeConfig("platform:\n  generic:\n    default:\n      base_url: 'http://localhost'\n      api_key: '%env(PROVIDER_API_KEY)%'\nmodel: 'gpt-4'\n");

        $this->expectException(MissingEnvironmentVariableException::class);
        $this->expectExceptionMessage('PROVIDER_API_KEY');

        $this->resolvedMcpServeCommand()->getCommand();
    }

    private function writeConfig(string $yaml): void
    {
        $this->filesystem->dumpFile($this->configHome.'/symfony-security-auditor/config.yaml', $yaml);
    }

    private function resolvedMcpServeCommand(): LazyCommand
    {
        $command = StandaloneApplicationFactory::fromEnvironment([
            'XDG_CONFIG_HOME' => $this->configHome,
            'XDG_CACHE_HOME' => $this->cacheHome,
        ])->create()->get(McpServeCommand::NAME);
        self::assertInstanceOf(LazyCommand::class, $command);

        return $command;
    }
}
