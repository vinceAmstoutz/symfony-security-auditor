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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Advisory;

use PHPUnit\Framework\TestCase;
use Symfony\Component\Process\Process;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\Exception\AdvisorySourceUnavailableException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\SymfonyProcessComposerAuditRunner;

final class SymfonyProcessComposerAuditRunnerTest extends TestCase
{
    public function test_it_returns_stdout_when_process_emits_json(): void
    {
        $symfonyProcessComposerAuditRunner = new SymfonyProcessComposerAuditRunner(
            processBuilder: static fn (string $path): Process => new Process(['printf', '%s', '{"advisories":{}}']),
        );

        $output = $symfonyProcessComposerAuditRunner->run('/app');

        self::assertJson($output);
        self::assertSame('{"advisories":{}}', $output);
    }

    public function test_it_throws_advisory_unavailable_when_stdout_is_empty(): void
    {
        $symfonyProcessComposerAuditRunner = new SymfonyProcessComposerAuditRunner(
            processBuilder: static fn (string $path): Process => new Process(['true']),
        );

        $this->expectException(AdvisorySourceUnavailableException::class);
        $this->expectExceptionMessage('Composer audit failed for project "/some/path"');

        $symfonyProcessComposerAuditRunner->run('/some/path');
    }

    public function test_empty_stdout_message_falls_back_to_empty_stdout_label_when_stderr_also_empty(): void
    {
        $symfonyProcessComposerAuditRunner = new SymfonyProcessComposerAuditRunner(
            processBuilder: static fn (string $path): Process => new Process(['true']),
        );

        try {
            $symfonyProcessComposerAuditRunner->run('/some/path');
            self::fail('Expected AdvisorySourceUnavailableException');
        } catch (AdvisorySourceUnavailableException $advisorySourceUnavailableException) {
            self::assertStringContainsString('empty stdout', $advisorySourceUnavailableException->getMessage());
        }
    }

    public function test_empty_stdout_message_includes_stderr_when_present(): void
    {
        $symfonyProcessComposerAuditRunner = new SymfonyProcessComposerAuditRunner(
            processBuilder: static fn (string $path): Process => Process::fromShellCommandline('printf "boom" 1>&2; true'),
        );

        try {
            $symfonyProcessComposerAuditRunner->run('/some/path');
            self::fail('Expected AdvisorySourceUnavailableException');
        } catch (AdvisorySourceUnavailableException $advisorySourceUnavailableException) {
            self::assertStringContainsString('boom', $advisorySourceUnavailableException->getMessage());
        }
    }

    public function test_default_process_builder_uses_composer_audit_command_with_required_flags(): void
    {
        $process = (SymfonyProcessComposerAuditRunner::defaultProcessBuilder())('/some/path');

        $commandLine = $process->getCommandLine();
        self::assertStringContainsString("'composer'", $commandLine);
        self::assertStringContainsString("'audit'", $commandLine);
        self::assertStringContainsString("'--format=json'", $commandLine);
        self::assertStringContainsString("'--locked'", $commandLine);
        self::assertStringContainsString("'--no-interaction'", $commandLine);
    }

    public function test_it_throws_when_stdout_is_only_whitespace(): void
    {
        $symfonyProcessComposerAuditRunner = new SymfonyProcessComposerAuditRunner(
            processBuilder: static fn (string $path): Process => Process::fromShellCommandline('printf "   "; false'),
        );

        $this->expectException(AdvisorySourceUnavailableException::class);

        $symfonyProcessComposerAuditRunner->run('/some/path');
    }

    public function test_it_wraps_process_exception_as_binary_not_found_when_setup_throws(): void
    {
        $symfonyProcessComposerAuditRunner = new SymfonyProcessComposerAuditRunner(
            timeoutSeconds: -1,
            processBuilder: static fn (string $path): Process => new Process(['true']),
        );

        $this->expectException(AdvisorySourceUnavailableException::class);
        $this->expectExceptionMessage('composer binary not found on PATH');

        $symfonyProcessComposerAuditRunner->run('/app');
    }
}
