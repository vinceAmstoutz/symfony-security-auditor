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
use Symfony\AI\Platform\Exception\ExceedContextSizeException;
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

final class CodexPlatformTest extends TestCase
{
    private const string ANSWER = '{"type":"item.completed","item":{"id":"item_0","type":"agent_message","text":"OK"}}';

    private string $workingDirectory;

    #[Override]
    protected function setUp(): void
    {
        $this->workingDirectory = sys_get_temp_dir().'/ssa-codex-'.bin2hex(random_bytes(6));
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
    public function test_the_codex_cli_runs_with_its_shell_off(): void
    {
        $this->invoke([]);

        self::assertContains(['--config', 'features.shell_tool=false'], $this->consecutiveArgumentPairs());
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
    public function test_the_codex_cli_runs_read_only_without_web_search_and_ignores_the_configuration_of_the_machine(): void
    {
        $this->invoke([]);

        self::assertSame(
            ['exec', '--json', '--sandbox', 'read-only', '--skip-git-repo-check', '--ephemeral', '--ignore-user-config', '--ignore-rules', '--config', 'features.shell_tool=false', '--config', 'web_search="disabled"', '--model', 'gpt-5.4'],
            \array_slice($this->arguments(), 0, -1),
        );
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
    public function test_the_codex_cli_takes_both_prompts_in_one_command_line_argument_so_they_are_measured_together(): void
    {
        $platform = $this->container()->get(PlatformInterface::class);
        self::assertInstanceOf(PlatformInterface::class, $platform);

        $this->expectException(ExceedContextSizeException::class);

        $platform->invoke('gpt-5.4', new MessageBag(Message::forSystem(str_repeat('a', 70000)), Message::ofUser(str_repeat('b', 70000))));
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

        return $platform->invoke('gpt-5.4', new MessageBag(Message::forSystem('Be terse.'), Message::ofUser('Audit this.')), $options)->asText();
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
            new StandaloneConfig([], new StandalonePlatformConfig(['codex' => ['cli_binary' => $this->fakeCli()]], 'codex')),
            $this->workingDirectory.'/cache',
        );
    }

    private function fakeCli(): string
    {
        $cli = $this->workingDirectory.'/codex';
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
