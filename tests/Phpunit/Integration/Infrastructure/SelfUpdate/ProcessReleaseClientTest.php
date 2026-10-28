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

use Ergebnis\PHPUnit\SlowTestDetector\Attribute\MaximumDuration;
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
    public function test_get_bounds_the_transfer_and_the_body_tightly_and_passes_the_url(): void
    {
        $captured = [];
        $processReleaseClient = new ProcessReleaseClient(static function (array $arguments) use (&$captured): Process {
            $captured = $arguments;

            return Process::fromShellCommandline('printf %s BODY');
        });

        $processReleaseClient->get('https://example.test/resource');

        self::assertSame(['--max-time', '20', '--max-filesize', '1048576', 'https://example.test/resource'], $captured);
    }

    /**
     * @throws SelfUpdateFailedException
     */
    public function test_download_keeps_a_generous_transfer_and_body_bound_and_targets_the_destination(): void
    {
        $captured = [];
        $destination = $this->workingDirectory.'/asset';
        $processReleaseClient = new ProcessReleaseClient(static function (array $arguments) use (&$captured): Process {
            $captured = $arguments;

            return Process::fromShellCommandline('true');
        });

        $processReleaseClient->download('https://example.test/asset', $destination);

        self::assertSame(['--max-time', '600', '--output', $destination, '--max-filesize', '268435456', 'https://example.test/asset'], $captured);
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
    #[MaximumDuration(4000)]
    public function test_download_reports_the_bytes_received_while_it_runs_and_once_it_ends(): void
    {
        $destination = $this->workingDirectory.'/asset';
        $processReleaseClient = new ProcessReleaseClient(static fn (array $arguments): Process => Process::fromShellCommandline(\sprintf('printf A > %1$s; sleep 1; printf BB >> %1$s', escapeshellarg($arguments[3]))));
        $receivedBytes = [];

        $processReleaseClient->download('https://example.test/asset', $destination, static function (int $bytes) use (&$receivedBytes): void {
            $receivedBytes[] = $bytes;
        });

        self::assertSame([1, 3], array_values(array_unique(array_filter($receivedBytes, static fn (int $bytes): bool => 0 < $bytes))));
    }

    /**
     * @throws SelfUpdateFailedException
     */
    public function test_a_download_that_wrote_nothing_reports_no_byte(): void
    {
        $processReleaseClient = new ProcessReleaseClient(static fn (array $arguments): Process => new Process(['true']));
        $receivedBytes = [];

        $processReleaseClient->download('https://example.test/asset', $this->workingDirectory.'/asset', static function (int $bytes) use (&$receivedBytes): void {
            $receivedBytes[] = $bytes;
        });

        self::assertSame([0], array_values(array_unique($receivedBytes)));
    }

    /**
     * @throws SelfUpdateFailedException
     */
    #[MaximumDuration(4000)]
    public function test_a_download_that_outlives_its_process_timeout_fails(): void
    {
        $processReleaseClient = new ProcessReleaseClient(static function (array $arguments): Process {
            $process = Process::fromShellCommandline('sleep 5');
            $process->setTimeout(0.5);

            return $process;
        });

        $this->expectException(SelfUpdateFailedException::class);

        $processReleaseClient->download('https://example.test/asset', $this->workingDirectory.'/asset', static function (int $bytes): void {});
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

    public function test_default_process_builder_keeps_every_transfer_and_redirect_on_https_with_tls_1_2_or_newer(): void
    {
        $process = (ProcessReleaseClient::defaultProcessBuilder())(['https://example.test/asset']);

        self::assertSame(
            "'curl' '-fsSL' '--proto' '=https' '--tlsv1.2' '--connect-timeout' '10' '-H' 'User-Agent: symfony-security-auditor-self-update' 'https://example.test/asset'",
            $process->getCommandLine(),
        );
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
