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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Scan;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Scan\ScanPathFilter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;

final class ScanPathFilterTest extends TestCase
{
    public function test_empty_scan_paths_return_input_unchanged(): void
    {
        $files = [$this->file('src/A.php'), $this->file('tests/A.php')];

        self::assertSame($files, ScanPathFilter::apply($files, []));
    }

    public function test_keeps_files_below_a_scan_path(): void
    {
        $projectFile = $this->file('apps/api/src/Controller/A.php');
        $dropped = $this->file('apps/web/src/Controller/B.php');

        $filtered = ScanPathFilter::apply([$projectFile, $dropped], ['apps/api']);

        self::assertSame([$projectFile], $filtered);
    }

    public function test_supports_several_scan_paths(): void
    {
        $projectFile = $this->file('apps/api/src/A.php');
        $libFile = $this->file('libs/shared/src/B.php');
        $otherFile = $this->file('docs/index.md');

        $filtered = ScanPathFilter::apply(
            [$projectFile, $libFile, $otherFile],
            ['apps/api', 'libs/shared'],
        );

        self::assertSame([$projectFile, $libFile], $filtered);
    }

    public function test_does_not_match_paths_that_only_share_a_prefix(): void
    {
        $projectFile = $this->file('apps/api/src/A.php');
        $apiShared = $this->file('apps/api-shared/src/B.php');

        $filtered = ScanPathFilter::apply([$projectFile, $apiShared], ['apps/api']);

        self::assertSame([$projectFile], $filtered);
    }

    public function test_keeps_a_file_whose_relative_path_equals_the_scan_path(): void
    {
        $projectFile = $this->file('README.md');

        $filtered = ScanPathFilter::apply([$projectFile], ['README.md']);

        self::assertSame([$projectFile], $filtered);
    }

    public function test_normalizes_trailing_separator_in_scan_path(): void
    {
        $projectFile = $this->file('apps/api/src/A.php');

        $filtered = ScanPathFilter::apply([$projectFile], ['apps/api/']);

        self::assertSame([$projectFile], $filtered);
    }

    public function test_blank_scan_paths_are_dropped_and_treated_as_no_filter(): void
    {
        $files = [$this->file('src/A.php'), $this->file('tests/A.php')];

        self::assertSame($files, ScanPathFilter::apply($files, ['   ', '']));
    }

    public function test_normalizes_windows_separators_in_project_files(): void
    {
        $projectFile = ProjectFile::create('apps\\api\\src\\A.php', '/app/apps/api/src/A.php', '<?php');

        $filtered = ScanPathFilter::apply([$projectFile], ['apps/api']);

        self::assertSame([$projectFile], $filtered);
    }

    public function test_returns_empty_when_no_file_matches(): void
    {
        $filtered = ScanPathFilter::apply([$this->file('src/A.php')], ['apps/api']);

        self::assertSame([], $filtered);
    }

    public function test_blank_entries_do_not_short_circuit_subsequent_scan_paths(): void
    {
        // Pins the `continue` inside the normalize loop against a `break` mutant.
        // With `continue` (correct), the blank entry is skipped and 'apps/api' is
        // still added to the filter. With `break` (mutant), the loop exits before
        // 'apps/api' is normalized, leaving the filter empty and returning every
        // input file (including the one that should have been dropped).
        $projectFile = $this->file('apps/api/src/A.php');
        $dropped = $this->file('apps/web/src/B.php');

        $filtered = ScanPathFilter::apply([$projectFile, $dropped], ['', 'apps/api']);

        self::assertSame([$projectFile], $filtered);
    }

    public function test_backslashes_in_scan_path_are_normalized_to_forward_slashes(): void
    {
        // Pins the `str_replace('\\', '/', $trimmed)` call against UnwrapStrReplace.
        // Without normalization (mutant), 'apps\\api' would not match 'apps/api/...'.
        $projectFile = $this->file('apps/api/src/A.php');

        $filtered = ScanPathFilter::apply([$projectFile], ['apps\\api']);

        self::assertSame([$projectFile], $filtered);
    }

    public function test_file_matching_multiple_scan_paths_is_added_only_once(): void
    {
        // Pins the `break` inside the per-file prefix loop against a `continue` mutant.
        // With `break` (correct), a file matching the first prefix is added and the
        // inner loop exits. With `continue` (mutant), the file is appended once per
        // matching prefix — here 'apps/api' and 'apps/api/src' both match, so the
        // mutant would emit the file twice.
        $file = $this->file('apps/api/src/A.php');

        $filtered = ScanPathFilter::apply([$file], ['apps/api', 'apps/api/src']);

        self::assertCount(1, $filtered);
    }

    private function file(string $relativePath): ProjectFile
    {
        return ProjectFile::create($relativePath, '/abs/'.$relativePath, '<?php');
    }
}
