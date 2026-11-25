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
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Process\Process;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\Exception\AdvisorySourceUnavailableException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\SymfonyProcessComposerAuditRunner;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\ComposerPhar;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\EmbeddedComposer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\SelfInvocation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\XdgConfigPathResolver;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Fixture\ExpectsExceptionMessageTrait;

final class SymfonyProcessComposerAuditRunnerTest extends TestCase
{
    use ExpectsExceptionMessageTrait;

    /**
     * @throws AdvisorySourceUnavailableException
     */
    public function test_it_returns_stdout_when_process_emits_json(): void
    {
        $symfonyProcessComposerAuditRunner = new SymfonyProcessComposerAuditRunner(
            processBuilder: static fn (string $path): Process => new Process(['printf', '%s', '{"advisories":{}}']),
        );

        $output = $symfonyProcessComposerAuditRunner->run('/app');

        self::assertJson($output);
        self::assertSame('{"advisories":{}}', $output);
    }

    /**
     * @throws AdvisorySourceUnavailableException
     */
    public function test_it_throws_advisory_unavailable_when_stdout_is_empty(): void
    {
        $symfonyProcessComposerAuditRunner = new SymfonyProcessComposerAuditRunner(
            processBuilder: static fn (string $path): Process => new Process(['true']),
        );

        $this->expectException(AdvisorySourceUnavailableException::class);
        $this->expectExceptionMessageContaining('Composer audit failed for project "/some/path"');

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

    /**
     * @throws AdvisorySourceUnavailableException
     */
    public function test_it_reports_a_missing_binary_distinctly_instead_of_a_generic_failed_process(): void
    {
        $symfonyProcessComposerAuditRunner = new SymfonyProcessComposerAuditRunner(
            processBuilder: static fn (string $path): Process => new Process(['definitely-not-a-real-binary-composer-xyz']),
        );

        $this->expectException(AdvisorySourceUnavailableException::class);
        $this->expectExceptionMessageContaining('composer binary not found on PATH; cannot run advisory audit');

        $symfonyProcessComposerAuditRunner->run('/some/path');
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

    /**
     * The audited project's `pre-command-run` script or a plugin in its
     * `vendor/` would run arbitrary commands on the audit host.
     */
    public function test_default_process_builder_refuses_the_audited_projects_scripts_and_plugins(): void
    {
        $commandLine = (SymfonyProcessComposerAuditRunner::defaultProcessBuilder())('/some/path')->getCommandLine();

        self::assertStringContainsString("'--no-scripts'", $commandLine);
        self::assertStringContainsString("'--no-plugins'", $commandLine);
    }

    /**
     * @throws AdvisorySourceUnavailableException
     */
    public function test_it_throws_when_stdout_is_only_whitespace(): void
    {
        $symfonyProcessComposerAuditRunner = new SymfonyProcessComposerAuditRunner(
            processBuilder: static fn (string $path): Process => Process::fromShellCommandline('printf "   "; false'),
        );

        $this->expectException(AdvisorySourceUnavailableException::class);

        $symfonyProcessComposerAuditRunner->run('/some/path');
    }

    /**
     * @throws AdvisorySourceUnavailableException
     */
    public function test_it_reports_the_real_reason_when_process_setup_throws_for_a_cause_other_than_a_timeout(): void
    {
        $symfonyProcessComposerAuditRunner = new SymfonyProcessComposerAuditRunner(
            timeoutSeconds: -1,
            processBuilder: static fn (string $path): Process => new Process(['true']),
        );

        $this->expectException(AdvisorySourceUnavailableException::class);
        $this->expectExceptionMessageContaining('The timeout value must be a valid positive integer or float number.');

        $symfonyProcessComposerAuditRunner->run('/app');
    }

    /**
     * @throws AdvisorySourceUnavailableException
     */
    public function test_it_reports_a_timeout_distinctly_instead_of_mislabeling_it_as_a_missing_binary(): void
    {
        $symfonyProcessComposerAuditRunner = new SymfonyProcessComposerAuditRunner(
            timeoutSeconds: 0.1,
            processBuilder: static fn (string $path): Process => Process::fromShellCommandline('sleep 2'),
        );

        $this->expectException(AdvisorySourceUnavailableException::class);
        $this->expectExceptionMessageContaining('composer audit timed out after 0.1 seconds');

        $symfonyProcessComposerAuditRunner->run('/app');
    }

    /**
     * @throws AdvisorySourceUnavailableException
     */
    public function test_embedded_process_builder_audits_with_the_composer_the_binary_bundles(): void
    {
        $workspace = sys_get_temp_dir().'/ssa-embedded-audit-'.bin2hex(random_bytes(6));
        $fixturePhar = __DIR__.'/../../../Fixture/Composer/composer.phar';
        $symfonyProcessComposerAuditRunner = new SymfonyProcessComposerAuditRunner(processBuilder: SymfonyProcessComposerAuditRunner::embeddedProcessBuilder(new EmbeddedComposer(
            new SelfInvocation(\dirname(__DIR__, 4).'/bin/symfony-security-auditor', 'cli', \PHP_BINARY),
            new ComposerPhar($fixturePhar, (string) hash_file('sha256', $fixturePhar)),
        ), new XdgConfigPathResolver(null, null, null, $workspace.'/data')));

        try {
            self::assertSame('fixture composer', $symfonyProcessComposerAuditRunner->run($workspace));
        } finally {
            (new Filesystem())->remove($workspace);
        }
    }

    /**
     * @throws AdvisorySourceUnavailableException
     */
    public function test_a_bundled_composer_that_cannot_be_unpacked_leaves_the_advisory_source_unavailable(): void
    {
        $workspace = sys_get_temp_dir().'/ssa-embedded-audit-'.bin2hex(random_bytes(6));
        $symfonyProcessComposerAuditRunner = new SymfonyProcessComposerAuditRunner(processBuilder: SymfonyProcessComposerAuditRunner::embeddedProcessBuilder(new EmbeddedComposer(
            new SelfInvocation('/opt/symfony-security-auditor', 'cli', '/usr/bin/php'),
            new ComposerPhar($workspace.'/missing/composer.phar'),
        ), new XdgConfigPathResolver(null, null, null, $workspace.'/data')));

        $this->expectException(AdvisorySourceUnavailableException::class);
        $this->expectExceptionMessageContaining('missing/composer.phar');

        $symfonyProcessComposerAuditRunner->run($workspace);
    }

    public function test_embedded_process_builder_keeps_the_users_composer_home(): void
    {
        $workspace = sys_get_temp_dir().'/ssa-embedded-audit-'.bin2hex(random_bytes(6));
        $fixturePhar = __DIR__.'/../../../Fixture/Composer/composer.phar';
        $processBuilder = SymfonyProcessComposerAuditRunner::embeddedProcessBuilder(new EmbeddedComposer(
            new SelfInvocation('/opt/symfony-security-auditor', 'cli', '/usr/bin/php'),
            new ComposerPhar($fixturePhar, (string) hash_file('sha256', $fixturePhar)),
        ), new XdgConfigPathResolver(null, null, null, $workspace.'/data'));

        try {
            $env = $processBuilder($workspace)->getEnv();
        } finally {
            (new Filesystem())->remove($workspace);
        }

        self::assertSame([], array_intersect_key($env, ['COMPOSER_HOME' => true, 'COMPOSER_CACHE_DIR' => true]));
    }

    public function test_embedded_process_builder_audits_in_the_directory_it_is_given(): void
    {
        $workspace = sys_get_temp_dir().'/ssa-embedded-audit-'.bin2hex(random_bytes(6));
        $fixturePhar = __DIR__.'/../../../Fixture/Composer/composer.phar';
        $processBuilder = SymfonyProcessComposerAuditRunner::embeddedProcessBuilder(new EmbeddedComposer(
            new SelfInvocation('/opt/symfony-security-auditor', 'cli', '/usr/bin/php'),
            new ComposerPhar($fixturePhar, (string) hash_file('sha256', $fixturePhar)),
        ), new XdgConfigPathResolver(null, null, null, $workspace.'/data'));

        try {
            $workingDirectory = $processBuilder($workspace)->getWorkingDirectory();
        } finally {
            (new Filesystem())->remove($workspace);
        }

        self::assertSame($workspace, $workingDirectory);
    }

    public function test_embedded_process_builder_unpacks_composer_in_the_data_directory_not_in_the_workspace(): void
    {
        $directory = sys_get_temp_dir().'/ssa-embedded-audit-'.bin2hex(random_bytes(6));
        $fixturePhar = __DIR__.'/../../../Fixture/Composer/composer.phar';
        $processBuilder = SymfonyProcessComposerAuditRunner::embeddedProcessBuilder(
            new EmbeddedComposer(new SelfInvocation('/opt/symfony-security-auditor', 'cli', '/usr/bin/php'), new ComposerPhar($fixturePhar, (string) hash_file('sha256', $fixturePhar))),
            new XdgConfigPathResolver(null, null, null, $directory.'/data'),
        );

        try {
            $processBuilder($directory.'/workspace');
            $unpacked = [is_dir($directory.'/workspace/.composer'), is_dir($directory.'/data/symfony-security-auditor/.composer')];
        } finally {
            (new Filesystem())->remove($directory);
        }

        self::assertSame([false, true], $unpacked);
    }

    /**
     * @throws AdvisorySourceUnavailableException
     */
    public function test_no_home_directory_leaves_the_advisory_source_unavailable(): void
    {
        $fixturePhar = __DIR__.'/../../../Fixture/Composer/composer.phar';
        $symfonyProcessComposerAuditRunner = new SymfonyProcessComposerAuditRunner(processBuilder: SymfonyProcessComposerAuditRunner::embeddedProcessBuilder(
            new EmbeddedComposer(new SelfInvocation('/opt/symfony-security-auditor', 'cli', '/usr/bin/php'), new ComposerPhar($fixturePhar, (string) hash_file('sha256', $fixturePhar))),
            new XdgConfigPathResolver(null, null, null),
        ));

        $this->expectException(AdvisorySourceUnavailableException::class);

        $symfonyProcessComposerAuditRunner->run(sys_get_temp_dir());
    }
}
