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

use Override;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Filesystem\Exception\IOException;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\ComposerAuditRunnerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\Exception\AdvisorySourceUnavailableException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\IsolatedComposerAuditRunner;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\SymfonyProcessComposerAuditRunner;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Advisory\Fixture\WorkspaceInspectingComposerAuditRunner;

final class IsolatedComposerAuditRunnerTest extends TestCase
{
    private const string HOSTILE_MANIFEST = '{"repositories": [{"type": "composer", "url": "http://169.254.169.254/"}]}';

    private const string LOCKFILE = '{"packages": [{"name": "vendor/foo", "version": "1.0.0"}]}';

    private string $projectDir;

    private string $binDir;

    private string $originalPath;

    /**
     * @throws AdvisorySourceUnavailableException
     */
    public function test_composer_runs_against_an_empty_manifest_and_a_copy_of_the_lockfile_outside_the_project(): void
    {
        $seen = $this->runFakeComposer();

        self::assertNotSame(realpath($this->projectDir), $seen['cwd']);
        self::assertSame([], $seen['composer_json']);
        self::assertSame(['packages' => [['name' => 'vendor/foo', 'version' => '1.0.0']]], $seen['lock']);
    }

    /**
     * @throws AdvisorySourceUnavailableException
     */
    public function test_composer_still_audits_the_locked_dependencies_without_scripts_or_plugins(): void
    {
        $seen = $this->runFakeComposer();

        self::assertSame('audit --format=json --locked --no-interaction --no-scripts --no-plugins', $seen['arguments']);
    }

    /**
     * @throws AdvisorySourceUnavailableException
     */
    public function test_the_private_copy_is_removed_once_the_audit_is_done(): void
    {
        $seen = $this->runFakeComposer();

        self::assertDirectoryDoesNotExist($seen['cwd']);
    }

    /**
     * @throws AdvisorySourceUnavailableException
     */
    public function test_it_hands_the_decorated_runner_a_private_directory_holding_only_the_lockfile_and_an_empty_manifest(): void
    {
        $workspaceInspectingComposerAuditRunner = new WorkspaceInspectingComposerAuditRunner('{"advisories": {"vendor/foo": []}}');
        $isolatedComposerAuditRunner = new IsolatedComposerAuditRunner($workspaceInspectingComposerAuditRunner, new Filesystem());

        $payload = $isolatedComposerAuditRunner->run($this->projectDir);

        self::assertSame('{"advisories": {"vendor/foo": []}}', $payload);
        self::assertNotSame($this->projectDir, $workspaceInspectingComposerAuditRunner->workspace);
        self::assertSame("{}\n", $workspaceInspectingComposerAuditRunner->manifest);
        self::assertSame(self::LOCKFILE, $workspaceInspectingComposerAuditRunner->lockfile);
        self::assertSame('0700', $workspaceInspectingComposerAuditRunner->workspacePermissions);
    }

    /**
     * @throws AdvisorySourceUnavailableException
     */
    public function test_it_copies_the_lockfile_of_a_project_whose_name_is_not_valid_utf8(): void
    {
        $project = $this->projectDir."/jos\xE9/";
        mkdir($project, 0o777, true);
        file_put_contents($project.'composer.lock', '{"packages": []}');
        $workspaceInspectingComposerAuditRunner = new WorkspaceInspectingComposerAuditRunner();

        (new IsolatedComposerAuditRunner($workspaceInspectingComposerAuditRunner, new Filesystem()))->run($project);

        self::assertSame('{"packages": []}', $workspaceInspectingComposerAuditRunner->lockfile);
    }

    /**
     * @throws AdvisorySourceUnavailableException
     */
    public function test_each_run_gets_a_directory_of_its_own(): void
    {
        $workspaceInspectingComposerAuditRunner = new WorkspaceInspectingComposerAuditRunner();
        $isolatedComposerAuditRunner = new IsolatedComposerAuditRunner($workspaceInspectingComposerAuditRunner, new Filesystem());

        $isolatedComposerAuditRunner->run($this->projectDir);

        $firstWorkspace = $workspaceInspectingComposerAuditRunner->workspace;
        $isolatedComposerAuditRunner->run($this->projectDir);

        self::assertNotSame($firstWorkspace, $workspaceInspectingComposerAuditRunner->workspace);
    }

    /**
     * @throws AdvisorySourceUnavailableException
     */
    public function test_the_private_directory_is_named_with_sixteen_random_hex_characters_under_the_system_temp_directory(): void
    {
        $workspaceInspectingComposerAuditRunner = new WorkspaceInspectingComposerAuditRunner();
        $isolatedComposerAuditRunner = new IsolatedComposerAuditRunner($workspaceInspectingComposerAuditRunner, new Filesystem());

        $isolatedComposerAuditRunner->run($this->projectDir);

        self::assertMatchesRegularExpression(
            '#^'.preg_quote(sys_get_temp_dir(), '#').'/symfony-security-auditor-composer-[0-9a-f]{16}$#',
            (string) $workspaceInspectingComposerAuditRunner->workspace,
        );
    }

    /**
     * @throws AdvisorySourceUnavailableException
     */
    public function test_a_trailing_slash_on_the_project_path_does_not_double_the_separator_before_the_lockfile(): void
    {
        $filesystem = new class extends Filesystem {
            /**
             * @var list<string>
             */
            public array $existenceChecks = [];

            /**
             * @param iterable<mixed>|string $files
             */
            #[Override]
            public function exists(string|iterable $files): bool
            {
                if (\is_string($files)) {
                    $this->existenceChecks[] = $files;
                }

                return parent::exists($files);
            }
        };
        $isolatedComposerAuditRunner = new IsolatedComposerAuditRunner(new WorkspaceInspectingComposerAuditRunner(), $filesystem);

        $isolatedComposerAuditRunner->run($this->projectDir.'/');

        self::assertSame($this->projectDir.'/composer.lock', $filesystem->existenceChecks[0]);
    }

    public function test_the_private_copy_is_removed_when_the_decorated_runner_fails(): void
    {
        $workspaceInspectingComposerAuditRunner = new WorkspaceInspectingComposerAuditRunner(throwable: AdvisorySourceUnavailableException::forBinaryNotFound());
        $isolatedComposerAuditRunner = new IsolatedComposerAuditRunner($workspaceInspectingComposerAuditRunner, new Filesystem());

        try {
            $isolatedComposerAuditRunner->run($this->projectDir);
            self::fail('Expected AdvisorySourceUnavailableException');
        } catch (AdvisorySourceUnavailableException $advisorySourceUnavailableException) {
            self::assertSame('composer binary not found on PATH; cannot run advisory audit', $advisorySourceUnavailableException->getMessage());
            self::assertDirectoryDoesNotExist((string) $workspaceInspectingComposerAuditRunner->workspace);
        }
    }

    public function test_a_project_without_a_lockfile_is_refused_before_composer_runs(): void
    {
        unlink($this->projectDir.'/composer.lock');

        $this->assertRefusedWithoutRunningComposer('composer.lock does not exist');
    }

    public function test_a_symlinked_lockfile_is_refused_before_composer_runs(): void
    {
        unlink($this->projectDir.'/composer.lock');
        file_put_contents($this->projectDir.'/real.lock', self::LOCKFILE);
        symlink($this->projectDir.'/real.lock', $this->projectDir.'/composer.lock');

        $this->assertRefusedWithoutRunningComposer('composer.lock is a symlink');
    }

    public function test_a_lockfile_over_the_size_cap_is_refused_before_composer_runs(): void
    {
        $this->writeLockfileOfSize(IsolatedComposerAuditRunner::MAX_LOCKFILE_BYTES + 1);

        $this->assertRefusedWithoutRunningComposer(\sprintf('composer.lock is larger than %d bytes', IsolatedComposerAuditRunner::MAX_LOCKFILE_BYTES));
    }

    /**
     * @throws AdvisorySourceUnavailableException
     */
    public function test_a_lockfile_exactly_at_the_size_cap_is_copied(): void
    {
        $this->writeLockfileOfSize(IsolatedComposerAuditRunner::MAX_LOCKFILE_BYTES);
        $workspaceInspectingComposerAuditRunner = new WorkspaceInspectingComposerAuditRunner();
        $isolatedComposerAuditRunner = new IsolatedComposerAuditRunner($workspaceInspectingComposerAuditRunner, new Filesystem());

        $isolatedComposerAuditRunner->run($this->projectDir);

        self::assertSame(IsolatedComposerAuditRunner::MAX_LOCKFILE_BYTES, \strlen((string) $workspaceInspectingComposerAuditRunner->lockfile));
    }

    public function test_an_unreadable_lockfile_is_refused_with_the_reason_before_composer_runs(): void
    {
        $filesystem = new class extends Filesystem {
            #[Override]
            public function readFile(string $filename): string
            {
                throw new IOException('permission denied');
            }
        };
        $workspaceInspectingComposerAuditRunner = new WorkspaceInspectingComposerAuditRunner();
        $isolatedComposerAuditRunner = new IsolatedComposerAuditRunner($workspaceInspectingComposerAuditRunner, $filesystem);

        try {
            $isolatedComposerAuditRunner->run($this->projectDir);
            self::fail('Expected AdvisorySourceUnavailableException');
        } catch (AdvisorySourceUnavailableException $advisorySourceUnavailableException) {
            self::assertSame(\sprintf('Composer audit cannot use the lockfile of project "%s": permission denied', $this->projectDir), $advisorySourceUnavailableException->getMessage());
            self::assertInstanceOf(IOException::class, $advisorySourceUnavailableException->getPrevious());
            self::assertSame(0, $workspaceInspectingComposerAuditRunner->callCount);
        }
    }

    #[Override]
    protected function setUp(): void
    {
        $this->projectDir = sys_get_temp_dir().'/isolated_composer_project_'.uniqid('', true);
        $this->binDir = sys_get_temp_dir().'/isolated_composer_bin_'.uniqid('', true);
        mkdir($this->projectDir, 0o777, true);
        mkdir($this->binDir, 0o777, true);
        file_put_contents($this->projectDir.'/composer.json', self::HOSTILE_MANIFEST);
        file_put_contents($this->projectDir.'/composer.lock', self::LOCKFILE);
        $this->originalPath = (string) getenv('PATH');
    }

    #[Override]
    protected function tearDown(): void
    {
        putenv('PATH='.$this->originalPath);
        $filesystem = new Filesystem();
        $filesystem->remove($this->projectDir);
        $filesystem->remove($this->binDir);
    }

    /**
     * @return array{cwd: string, arguments: string, composer_json: mixed, lock: mixed}
     *
     * @throws AdvisorySourceUnavailableException
     */
    private function runFakeComposer(): array
    {
        $script = <<<'SH'
            #!/bin/sh
            printf '{"advisories":{},"cwd":"%s","arguments":"%s","composer_json":%s,"lock":%s}' "$(pwd -P)" "$*" "$(cat composer.json)" "$(cat composer.lock)"
            SH;
        file_put_contents($this->binDir.'/composer', $script."\n");
        chmod($this->binDir.'/composer', 0o755);
        putenv('PATH='.$this->binDir.\PATH_SEPARATOR.$this->originalPath);

        $seen = json_decode($this->runner()->run($this->projectDir), true, flags: \JSON_THROW_ON_ERROR);
        self::assertIsArray($seen);
        $cwd = $seen['cwd'] ?? null;
        $arguments = $seen['arguments'] ?? null;
        self::assertIsString($cwd);
        self::assertIsString($arguments);

        return ['cwd' => $cwd, 'arguments' => $arguments, 'composer_json' => $seen['composer_json'] ?? null, 'lock' => $seen['lock'] ?? null];
    }

    private function runner(): ComposerAuditRunnerInterface
    {
        return new IsolatedComposerAuditRunner(new SymfonyProcessComposerAuditRunner(), new Filesystem());
    }

    private function assertRefusedWithoutRunningComposer(string $reason): void
    {
        $workspaceInspectingComposerAuditRunner = new WorkspaceInspectingComposerAuditRunner();
        $isolatedComposerAuditRunner = new IsolatedComposerAuditRunner($workspaceInspectingComposerAuditRunner, new Filesystem());

        try {
            $isolatedComposerAuditRunner->run($this->projectDir);
            self::fail('Expected AdvisorySourceUnavailableException');
        } catch (AdvisorySourceUnavailableException $advisorySourceUnavailableException) {
            self::assertSame(\sprintf('Composer audit cannot use the lockfile of project "%s": %s', $this->projectDir, $reason), $advisorySourceUnavailableException->getMessage());
            self::assertSame(0, $workspaceInspectingComposerAuditRunner->callCount);
        }
    }

    /**
     * @param int<0, max> $bytes
     */
    private function writeLockfileOfSize(int $bytes): void
    {
        $handle = fopen($this->projectDir.'/composer.lock', 'w');
        self::assertIsResource($handle);
        ftruncate($handle, $bytes);
        fclose($handle);
    }
}
