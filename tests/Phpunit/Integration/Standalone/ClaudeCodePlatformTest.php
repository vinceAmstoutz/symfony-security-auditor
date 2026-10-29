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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Standalone;

use Ergebnis\PHPUnit\SlowTestDetector\Attribute\MaximumDuration;
use Override;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;
use Symfony\AI\Platform\Message\Message;
use Symfony\AI\Platform\Message\MessageBag;
use Symfony\AI\Platform\PlatformInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\NonLocalPlatformEndpointException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandaloneConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandalonePlatformConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\Exception\AmbiguousPlatformException;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\Exception\MissingBundleExtensionException;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\Exception\ProviderBridgeException;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\Exception\UnknownPlatformProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\StandaloneContainerFactory;

final class ClaudeCodePlatformTest extends TestCase
{
    private const string ANSWER = '{"type":"result","subtype":"success","is_error":false,"result":"OK","usage":{"input_tokens":3,"output_tokens":1}}';

    private string $workingDirectory;

    #[Override]
    protected function setUp(): void
    {
        $this->workingDirectory = sys_get_temp_dir().'/ssa-claude-code-'.bin2hex(random_bytes(6));
        (new Filesystem())->mkdir($this->workingDirectory);
    }

    #[Override]
    protected function tearDown(): void
    {
        (new Filesystem())->remove($this->workingDirectory);
    }

    /**
     * @throws AmbiguousPlatformException
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws NonLocalPlatformEndpointException
     * @throws ProviderBridgeException
     */
    #[RunInSeparateProcess]
    #[MaximumDuration(4000)]
    public function test_the_claude_code_cli_runs_with_its_built_in_tools_off(): void
    {
        $this->invoke([]);

        self::assertContains(['--tools', ''], $this->consecutiveArgumentPairs());
    }

    /**
     * @throws AmbiguousPlatformException
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws NonLocalPlatformEndpointException
     * @throws ProviderBridgeException
     */
    #[RunInSeparateProcess]
    #[MaximumDuration(4000)]
    public function test_the_claude_code_cli_ignores_the_mcp_servers_configured_on_the_machine(): void
    {
        $this->invoke([]);

        self::assertContains('--strict-mcp-config', $this->arguments());
    }

    /**
     * @throws AmbiguousPlatformException
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws NonLocalPlatformEndpointException
     * @throws ProviderBridgeException
     */
    #[RunInSeparateProcess]
    #[MaximumDuration(4000)]
    public function test_the_claude_code_cli_starts_outside_the_audited_project_so_its_files_cannot_configure_it(): void
    {
        $this->invoke([]);

        self::assertSame(realpath(sys_get_temp_dir()), trim((string) file_get_contents($this->workingDirectory.'/cwd')));
    }

    /**
     * @throws AmbiguousPlatformException
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws NonLocalPlatformEndpointException
     * @throws ProviderBridgeException
     */
    #[RunInSeparateProcess]
    #[MaximumDuration(4000)]
    public function test_the_audit_asks_the_claude_code_cli_for_json_answers_since_the_cli_cannot_carry_the_auditor_tools(): void
    {
        $containerBuilder = $this->container();

        self::assertSame(
            [false, false, false, false],
            [
                $containerBuilder->getParameter('symfony_security_auditor.audit.tools_enabled'),
                $containerBuilder->getParameter('symfony_security_auditor.audit.structured_collection'),
                $containerBuilder->getParameter('symfony_security_auditor.audit.reviewer_tools_enabled'),
                $containerBuilder->getParameter('symfony_security_auditor.audit.reviewer_structured_collection'),
            ],
        );
    }

    /**
     * @param array<string, mixed> $options
     *
     * @throws AmbiguousPlatformException
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws NonLocalPlatformEndpointException
     * @throws ProviderBridgeException
     */
    private function invoke(array $options): string
    {
        $platform = $this->container()->get(PlatformInterface::class);
        self::assertInstanceOf(PlatformInterface::class, $platform);

        return $platform->invoke('opus', new MessageBag(Message::forSystem('Be terse.'), Message::ofUser('Audit this.')), $options)->asText();
    }

    /**
     * @throws AmbiguousPlatformException
     * @throws MissingBundleExtensionException
     * @throws UnknownPlatformProviderException
     * @throws NonLocalPlatformEndpointException
     * @throws ProviderBridgeException
     */
    private function container(): ContainerBuilder
    {
        return (new StandaloneContainerFactory())->create(
            new StandaloneConfig([], new StandalonePlatformConfig(['claudecode' => ['cli_binary' => $this->fakeCli()]], 'claudecode')),
            $this->workingDirectory.'/cache',
        );
    }

    private function fakeCli(): string
    {
        $cli = $this->workingDirectory.'/claude';
        (new Filesystem())->dumpFile($cli, \sprintf("#!/bin/sh\npwd -P > %s\nprintf '%%s\\0' \"\$@\" > %s\necho '%s'\n", escapeshellarg($this->workingDirectory.'/cwd'), escapeshellarg($this->argumentsFile()), self::ANSWER));
        (new Filesystem())->chmod($cli, 0o755);

        return $cli;
    }

    private function argumentsFile(): string
    {
        return $this->workingDirectory.'/arguments';
    }

    /**
     * @return list<string>
     */
    private function arguments(): array
    {
        return explode("\0", rtrim((string) file_get_contents($this->argumentsFile()), "\0"));
    }

    /**
     * @return list<list<string>>
     */
    private function consecutiveArgumentPairs(): array
    {
        $arguments = $this->arguments();

        return array_map(static fn (int $index): array => [$arguments[$index], $arguments[$index + 1]], array_keys(\array_slice($arguments, 0, -1)));
    }
}
