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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Infrastructure\SelfUpdate;

use Override;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Process\Process;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\Exception\SelfUpdateFailedException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\ProcessReleaseClient;

final class ProcessReleaseClientTest extends TestCase
{
    private string $workingDirectory;

    #[Override]
    protected function setUp(): void
    {
        $this->workingDirectory = sys_get_temp_dir().'/ssa-release-'.bin2hex(random_bytes(6));
        (new Filesystem())->mkdir($this->workingDirectory);
    }

    #[Override]
    protected function tearDown(): void
    {
        (new Filesystem())->remove($this->workingDirectory);
    }

    /**
     * @throws SelfUpdateFailedException
     */
    public function test_get_returns_the_process_output(): void
    {
        $processReleaseClient = new ProcessReleaseClient(static fn (array $arguments): Process => Process::fromShellCommandline('printf %s BODY'));

        self::assertSame('BODY', $processReleaseClient->get('https://example.test/resource'));
    }

    /**
     * @throws SelfUpdateFailedException
     */
    public function test_get_bounds_the_transfer_tightly_and_passes_the_url(): void
    {
        $captured = [];
        $processReleaseClient = new ProcessReleaseClient(static function (array $arguments) use (&$captured): Process {
            $captured = $arguments;

            return Process::fromShellCommandline('printf %s BODY');
        });

        $processReleaseClient->get('https://example.test/resource');

        self::assertSame(['--max-time', '20', 'https://example.test/resource'], $captured);
    }

    /**
     * @throws SelfUpdateFailedException
     */
    public function test_download_keeps_a_generous_transfer_bound_and_targets_the_destination(): void
    {
        $captured = [];
        $destination = $this->workingDirectory.'/asset';
        $processReleaseClient = new ProcessReleaseClient(static function (array $arguments) use (&$captured): Process {
            $captured = $arguments;

            return Process::fromShellCommandline('true');
        });

        $processReleaseClient->download('https://example.test/asset', $destination);

        self::assertSame(['--max-time', '600', '--output', $destination, 'https://example.test/asset'], $captured);
    }

    /**
     * @throws SelfUpdateFailedException
     */
    public function test_get_throws_when_the_process_reports_failure(): void
    {
        $processReleaseClient = new ProcessReleaseClient(static fn (array $arguments): Process => new Process(['false']));

        $this->expectException(SelfUpdateFailedException::class);

        $processReleaseClient->get('https://example.test/resource');
    }

    /**
     * @throws SelfUpdateFailedException
     */
    public function test_download_writes_the_response_to_the_destination(): void
    {
        $destination = $this->workingDirectory.'/asset';
        $processReleaseClient = new ProcessReleaseClient(static fn (array $arguments): Process => Process::fromShellCommandline(\sprintf('printf CONTENT > %s', escapeshellarg($arguments[3]))));

        $processReleaseClient->download('https://example.test/asset', $destination);

        self::assertStringEqualsFile($destination, 'CONTENT');
    }

    /**
     * @throws SelfUpdateFailedException
     */
    public function test_download_throws_when_the_process_reports_failure(): void
    {
        $processReleaseClient = new ProcessReleaseClient(static fn (array $arguments): Process => new Process(['false']));

        $this->expectException(SelfUpdateFailedException::class);

        $processReleaseClient->download('https://example.test/asset', $this->workingDirectory.'/asset');
    }

    /**
     * @throws SelfUpdateFailedException
     */
    public function test_it_throws_when_the_process_cannot_be_started(): void
    {
        $unlaunchableWorkingDirectory = $this->workingDirectory.'/missing-'.bin2hex(random_bytes(4));
        $processReleaseClient = new ProcessReleaseClient(static fn (array $arguments): Process => new Process(['true'], $unlaunchableWorkingDirectory));

        $this->expectException(SelfUpdateFailedException::class);

        $processReleaseClient->get('https://example.test/resource');
    }

    public function test_default_process_builder_uses_authenticated_curl(): void
    {
        $process = (ProcessReleaseClient::defaultProcessBuilder())(['--max-time', '600', '--output', '/tmp/asset', 'https://example.test/asset']);

        $commandLine = $process->getCommandLine();
        self::assertStringContainsString("'curl'", $commandLine);
        self::assertStringContainsString("'-fsSL'", $commandLine);
        self::assertStringContainsString("'--connect-timeout' '10'", $commandLine);
        self::assertStringContainsString("'--max-time' '600'", $commandLine);
        self::assertStringContainsString("'User-Agent: symfony-security-auditor-self-update'", $commandLine);
        self::assertStringContainsString("'https://example.test/asset'", $commandLine);
        self::assertSame(660.0, $process->getTimeout());
    }
}
