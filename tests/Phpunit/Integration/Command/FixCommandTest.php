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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Command;

use Override;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ExitCode;
use VinceAmstoutz\SymfonySecurityAuditor\Command\FixCommand;

final class FixCommandTest extends TestCase
{
    private const string VULNERABLE = "<?php\n\$id = \$request->get('id');\n\$sql = \"SELECT * FROM user WHERE id = \$id\";\n";

    private const string FIX = "```diff\n--- a/src/Repo.php\n+++ b/src/Repo.php\n@@ -2,2 +2,2 @@\n \$id = \$request->get('id');\n-\$sql = \"SELECT * FROM user WHERE id = \$id\";\n+\$sql = 'SELECT * FROM user WHERE id = ?';\n```";

    private Filesystem $filesystem;

    private string $tmpDir;

    #[Override]
    protected function setUp(): void
    {
        $this->filesystem = new Filesystem();
        $this->tmpDir = sys_get_temp_dir().'/fix_command_test_'.uniqid('', true);
        $this->filesystem->dumpFile($this->tmpDir.'/src/Repo.php', self::VULNERABLE);
    }

    #[Override]
    protected function tearDown(): void
    {
        $this->filesystem->remove($this->tmpDir);
    }

    public function test_a_dry_run_says_which_fix_applies_and_changes_no_file(): void
    {
        $commandTester = new CommandTester(new FixCommand());
        $commandTester->execute(['report' => $this->writeReport([$this->finding('SQL injection in Repo', self::FIX)]), 'project-path' => $this->tmpDir]);

        self::assertSame(
            [ExitCode::Success->value, true, true, self::VULNERABLE],
            [
                $commandTester->getStatusCode(),
                str_contains($commandTester->getDisplay(), 'SQL injection in Repo (src/Repo.php): applies cleanly'),
                str_contains($commandTester->getDisplay(), 'Dry run: no file was changed. Run again with --apply to write the 1 fix that applies.'),
                $this->filesystem->readFile($this->tmpDir.'/src/Repo.php'),
            ],
        );
    }

    public function test_apply_writes_the_fix_that_applies(): void
    {
        $commandTester = new CommandTester(new FixCommand());
        $commandTester->execute(['report' => $this->writeReport([$this->finding('SQL injection in Repo', self::FIX)]), 'project-path' => $this->tmpDir, '--apply' => true]);

        self::assertSame(
            [ExitCode::Success->value, "SQL injection in Repo (src/Repo.php): applied\n1 of 1 suggested fixes applied.\n", "<?php\n\$id = \$request->get('id');\n\$sql = 'SELECT * FROM user WHERE id = ?';\n"],
            [$commandTester->getStatusCode(), $commandTester->getDisplay(), $this->filesystem->readFile($this->tmpDir.'/src/Repo.php')],
        );
    }

    public function test_a_fix_for_code_that_changed_since_the_audit_is_refused_and_fails_the_run(): void
    {
        $this->filesystem->dumpFile($this->tmpDir.'/src/Repo.php', "<?php\n\$sql = \$repository->find(\$id);\n");
        $commandTester = new CommandTester(new FixCommand());
        $commandTester->execute(['report' => $this->writeReport([$this->finding('SQL injection in Repo', self::FIX)]), 'project-path' => $this->tmpDir, '--apply' => true]);

        self::assertSame(
            [ExitCode::Failure->value, "SQL injection in Repo (src/Repo.php): not applied, src/Repo.php is not a file inside the project, or its code changed since the audit\n0 of 1 suggested fixes applied.\n", "<?php\n\$sql = \$repository->find(\$id);\n"],
            [$commandTester->getStatusCode(), $commandTester->getDisplay(), $this->filesystem->readFile($this->tmpDir.'/src/Repo.php')],
        );
    }

    public function test_a_fix_through_a_symlink_is_refused(): void
    {
        $this->filesystem->dumpFile($this->tmpDir.'/outside/Repo.php', self::VULNERABLE);
        $this->filesystem->remove($this->tmpDir.'/src');
        $this->filesystem->symlink($this->tmpDir.'/outside', $this->tmpDir.'/src');

        $commandTester = new CommandTester(new FixCommand());
        $commandTester->execute(['report' => $this->writeReport([$this->finding('SQL injection in Repo', self::FIX)]), 'project-path' => $this->tmpDir, '--apply' => true]);

        self::assertSame([ExitCode::Failure->value, self::VULNERABLE], [$commandTester->getStatusCode(), $this->filesystem->readFile($this->tmpDir.'/outside/Repo.php')]);
    }

    public function test_a_fix_for_a_file_the_project_lacks_is_refused(): void
    {
        $commandTester = new CommandTester(new FixCommand());
        $commandTester->execute(['report' => $this->writeReport([$this->finding('Gone', str_replace('src/Repo.php', 'src/Gone.php', self::FIX), 'src/Gone.php')]), 'project-path' => $this->tmpDir, '--apply' => true]);

        self::assertSame([ExitCode::Failure->value, false], [$commandTester->getStatusCode(), $this->filesystem->exists($this->tmpDir.'/src/Gone.php')]);
    }

    public function test_a_fix_that_is_no_patch_is_refused(): void
    {
        $commandTester = new CommandTester(new FixCommand());
        $commandTester->execute(['report' => $this->writeReport([$this->finding('Prose', 'Use a prepared statement.')]), 'project-path' => $this->tmpDir]);

        self::assertSame(
            [ExitCode::Failure->value, "Prose (src/Repo.php): not applied, the suggested fix is not a patch the auditor can read\nDry run: no file was changed. Run again with --apply to write the 0 fixes that apply.\n"],
            [$commandTester->getStatusCode(), $commandTester->getDisplay()],
        );
    }

    public function test_two_fixes_to_one_file_apply_one_after_the_other(): void
    {
        $guard = "--- a/src/Repo.php\n+++ b/src/Repo.php\n@@ -1 +1,2 @@\n <?php\n+\$this->denyAccessUnlessGranted('ROLE_ADMIN');";
        $commandTester = new CommandTester(new FixCommand());
        $commandTester->execute(['report' => $this->writeReport([$this->finding('Guard', $guard), $this->finding('No fix', null), $this->finding('SQL injection in Repo', self::FIX)]), 'project-path' => $this->tmpDir, '--apply' => true]);

        self::assertSame(
            [ExitCode::Success->value, "<?php\n\$this->denyAccessUnlessGranted('ROLE_ADMIN');\n\$id = \$request->get('id');\n\$sql = 'SELECT * FROM user WHERE id = ?';\n", "Guard (src/Repo.php): applied\nSQL injection in Repo (src/Repo.php): applied\n2 of 2 suggested fixes applied.\n"],
            [$commandTester->getStatusCode(), $this->filesystem->readFile($this->tmpDir.'/src/Repo.php'), $commandTester->getDisplay()],
        );
    }

    public function test_a_dry_run_counts_every_fix_that_applies(): void
    {
        $guard = "--- a/src/Repo.php\n+++ b/src/Repo.php\n@@ -1 +1,2 @@\n <?php\n+\$this->denyAccessUnlessGranted('ROLE_ADMIN');";
        $commandTester = new CommandTester(new FixCommand());
        $commandTester->execute(['report' => $this->writeReport([$this->finding('Guard', $guard), $this->finding('SQL injection in Repo', self::FIX)]), 'project-path' => $this->tmpDir]);

        self::assertStringEndsWith("Dry run: no file was changed. Run again with --apply to write the 2 fixes that apply.\n", $commandTester->getDisplay());
    }

    public function test_a_report_it_cannot_read_fails_the_run(): void
    {
        $commandTester = new CommandTester(new FixCommand());
        $commandTester->execute(['report' => $this->tmpDir.'/missing.json', 'project-path' => $this->tmpDir]);

        self::assertSame([ExitCode::Failure->value, true], [$commandTester->getStatusCode(), str_contains($commandTester->getDisplay(), 'missing.json')]);
    }

    public function test_a_report_that_is_no_json_fails_the_run(): void
    {
        $this->filesystem->dumpFile($this->tmpDir.'/report.json', '{');
        $commandTester = new CommandTester(new FixCommand());
        $commandTester->execute(['report' => $this->tmpDir.'/report.json', 'project-path' => $this->tmpDir]);

        self::assertSame(ExitCode::Failure->value, $commandTester->getStatusCode());
    }

    public function test_a_report_without_findings_fails_the_run(): void
    {
        $this->filesystem->dumpFile($this->tmpDir.'/report.json', '{"grade": "A"}');
        $commandTester = new CommandTester(new FixCommand());
        $commandTester->execute(['report' => $this->tmpDir.'/report.json', 'project-path' => $this->tmpDir]);

        self::assertSame(ExitCode::Failure->value, $commandTester->getStatusCode());
    }

    public function test_an_entry_that_is_no_finding_with_a_fix_is_left_out(): void
    {
        $this->filesystem->dumpFile($this->tmpDir.'/report.json', json_encode(['vulnerabilities' => ['not a finding', ['title' => 'No file', 'file' => null, 'suggested_fix' => self::FIX], ['title' => 7, 'file' => 'src/Repo.php', 'suggested_fix' => self::FIX]]], \JSON_THROW_ON_ERROR));
        $commandTester = new CommandTester(new FixCommand());
        $commandTester->execute(['report' => $this->tmpDir.'/report.json', 'project-path' => $this->tmpDir]);

        self::assertSame([ExitCode::Success->value, "Dry run: no file was changed. Run again with --apply to write the 0 fixes that apply.\n"], [$commandTester->getStatusCode(), $commandTester->getDisplay()]);
    }

    public function test_a_project_path_that_is_no_directory_fails_the_run(): void
    {
        $commandTester = new CommandTester(new FixCommand());
        $commandTester->execute(['report' => $this->writeReport([$this->finding('SQL injection in Repo', self::FIX)]), 'project-path' => $this->tmpDir.'/missing']);

        self::assertSame([ExitCode::Failure->value, true], [$commandTester->getStatusCode(), str_contains((string) preg_replace('/\s+/', ' ', $commandTester->getDisplay()), 'is not a directory')]);
    }

    public function test_fixes_to_two_files_are_both_written(): void
    {
        $this->filesystem->dumpFile($this->tmpDir.'/src/Other.php', "x\n");
        $other = "--- a/src/Other.php\n+++ b/src/Other.php\n@@ -1 +1 @@\n-x\n+y";
        $commandTester = new CommandTester(new FixCommand());
        $commandTester->execute(['report' => $this->writeReport([$this->finding('SQL injection in Repo', self::FIX), $this->finding('Other', $other, 'src/Other.php')]), 'project-path' => $this->tmpDir, '--apply' => true]);

        self::assertSame(
            ["<?php\n\$id = \$request->get('id');\n\$sql = 'SELECT * FROM user WHERE id = ?';\n", "y\n"],
            [$this->filesystem->readFile($this->tmpDir.'/src/Repo.php'), $this->filesystem->readFile($this->tmpDir.'/src/Other.php')],
        );
    }

    public function test_a_section_of_a_fix_applies_to_what_its_earlier_section_left(): void
    {
        $this->filesystem->dumpFile($this->tmpDir.'/src/Repo.php', "a\nb\n");
        $first = "--- a/src/Repo.php\n+++ b/src/Repo.php\n@@ -1 +1 @@\n-a\n+A";
        $second = "--- a/src/Repo.php\n+++ b/src/Repo.php\n@@ -2 +2 @@\n-b\n+B\n--- a/src/Repo.php\n+++ b/src/Repo.php\n@@ -2 +2 @@\n-B\n+C";
        $commandTester = new CommandTester(new FixCommand());
        $commandTester->execute(['report' => $this->writeReport([$this->finding('First', $first), $this->finding('Second', $second)]), 'project-path' => $this->tmpDir, '--apply' => true]);

        self::assertSame([ExitCode::Success->value, "A\nC\n"], [$commandTester->getStatusCode(), $this->filesystem->readFile($this->tmpDir.'/src/Repo.php')]);
    }

    /**
     * @return array<string, mixed>
     */
    private function finding(string $title, ?string $suggestedFix, string $file = 'src/Repo.php'): array
    {
        return ['title' => $title, 'file' => $file, 'suggested_fix' => $suggestedFix];
    }

    /**
     * @param list<array<string, mixed>> $vulnerabilities
     */
    private function writeReport(array $vulnerabilities): string
    {
        $path = $this->tmpDir.'/report.json';
        $this->filesystem->dumpFile($path, json_encode(['vulnerabilities' => $vulnerabilities], \JSON_THROW_ON_ERROR));

        return $path;
    }
}
