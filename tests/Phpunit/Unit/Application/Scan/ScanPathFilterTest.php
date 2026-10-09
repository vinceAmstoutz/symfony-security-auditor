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

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Scan\ScanPathFilter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;

final class ScanPathFilterTest extends TestCase
{
    /**
     * @param list<string> $scanPaths
     */
    #[DataProvider('scopes')]
    public function test_it_says_whether_a_path_lies_in_the_scope_the_scan_applied(string $relativePath, array $scanPaths, bool $expected): void
    {
        self::assertSame($expected, ScanPathFilter::includes($relativePath, $scanPaths));
    }

    /**
     * @return iterable<string, array{string, list<string>, bool}>
     */
    public static function scopes(): iterable
    {
        yield 'the whole project' => ['src/A.php', [], true];
        yield 'a file below a scan path' => ['apps/api/src/A.php', ['apps/api'], true];
        yield 'a file equal to a scan path' => ['src/A.php', ['./src/A.php'], true];
        yield 'a file that only shares a prefix' => ['apps/api-shared/A.php', ['apps/api'], false];
        yield 'a file outside every scan path' => ['tests/A.php', ['src', 'config/'], false];
        yield 'a blank scan path' => ['tests/A.php', ['  '], true];
        yield 'a file below a scan path spelled with a parent segment' => ['src/Big.php', ['src/../src'], true];
        yield 'a file outside a scan path spelled with a parent segment' => ['src/Big.php', ['src/../tests'], false];
        yield 'a file below a scan path spelled with a current directory segment' => ['src/Controller/A.php', ['src/./Controller'], true];
        yield 'a file below a scan path spelled with an empty segment' => ['src/Controller/A.php', ['src//Controller'], true];
        yield 'a file below a scan path spelled with backslashes' => ['src/Controller/A.php', ['src\\..\\src\\Controller'], true];
    }

    /**
     * @param list<string> $scanPaths
     * @param list<string> $expected
     */
    #[DataProvider('spellings')]
    public function test_it_spells_every_scan_path_one_way(array $scanPaths, array $expected): void
    {
        self::assertSame($expected, ScanPathFilter::normalize($scanPaths));
    }

    /**
     * @return iterable<string, array{list<string>, list<string>}>
     */
    public static function spellings(): iterable
    {
        yield 'a plain directory' => [['src'], ['src']];
        yield 'surrounding whitespace' => [[' src '], ['src']];
        yield 'a trailing separator' => [['src/'], ['src']];
        yield 'a leading current directory segment' => [['./src'], ['src']];
        yield 'a current directory segment inside' => [['src/./Controller'], ['src/Controller']];
        yield 'an empty segment inside' => [['src//Controller'], ['src/Controller']];
        yield 'a parent segment inside' => [['src/../src'], ['src']];
        yield 'backslashes' => [['src\\..\\src\\Controller'], ['src/Controller']];
        yield 'a parent segment that leaves the project' => [['../shared'], ['../shared']];
        yield 'parent segments that climb above the start' => [['a/b/../../..'], ['..']];
        yield 'a name starting with a tilde' => [['~cache/src'], ['~cache/src']];
        yield 'a name that is not valid UTF-8' => [["src/caf\xE9"], ["src/caf\xE9"]];
        yield 'whitespace, a trailing separator and an empty segment around a name that is not valid UTF-8' => [[" src//caf\xE9/ "], ["src/caf\xE9"]];
        yield 'backslashes and a parent segment around a name that is not valid UTF-8' => [["lib\\..\\src\\caf\xE9"], ["src/caf\xE9"]];
        yield 'a name that is not valid UTF-8 beside a valid one' => [["caf\xE9", 'src'], ["caf\xE9", 'src']];
        yield 'a decomposed accent' => [["cafe\u{0301}"], ["caf\u{E9}"]];
        yield 'the project root' => [['.'], []];
        yield 'the project root reached through a parent segment' => [['src/..'], []];
        yield 'a separator alone' => [['/'], []];
        yield 'several paths in order, blank ones dropped' => [['b', '', 'a/../a', ' '], ['b', 'a']];
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_empty_scan_paths_return_input_unchanged(): void
    {
        $files = [$this->file('src/A.php'), $this->file('tests/A.php')];

        self::assertSame($files, ScanPathFilter::apply($files, []));
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_keeps_files_below_a_scan_path(): void
    {
        $projectFile = $this->file('apps/api/src/Controller/A.php');
        $dropped = $this->file('apps/web/src/Controller/B.php');

        $filtered = ScanPathFilter::apply([$projectFile, $dropped], ['apps/api']);

        self::assertSame([$projectFile], $filtered);
    }

    /**
     * @throws InvalidProjectFileException
     */
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

    /**
     * @throws InvalidProjectFileException
     */
    public function test_does_not_match_paths_that_only_share_a_prefix(): void
    {
        $projectFile = $this->file('apps/api/src/A.php');
        $apiShared = $this->file('apps/api-shared/src/B.php');

        $filtered = ScanPathFilter::apply([$projectFile, $apiShared], ['apps/api']);

        self::assertSame([$projectFile], $filtered);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_keeps_a_file_whose_relative_path_equals_the_scan_path(): void
    {
        $projectFile = $this->file('README.md');

        $filtered = ScanPathFilter::apply([$projectFile], ['README.md']);

        self::assertSame([$projectFile], $filtered);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_normalizes_trailing_separator_in_scan_path(): void
    {
        $projectFile = $this->file('apps/api/src/A.php');

        $filtered = ScanPathFilter::apply([$projectFile], ['apps/api/']);

        self::assertSame([$projectFile], $filtered);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_blank_scan_paths_are_dropped_and_treated_as_no_filter(): void
    {
        $files = [$this->file('src/A.php'), $this->file('tests/A.php')];

        self::assertSame($files, ScanPathFilter::apply($files, ['   ', '']));
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_a_slash_only_scan_path_is_dropped_and_treated_as_no_filter(): void
    {
        $files = [$this->file('src/A.php'), $this->file('tests/A.php')];

        self::assertSame($files, ScanPathFilter::apply($files, ['/']));
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_a_leading_dot_slash_segment_in_a_scan_path_still_matches(): void
    {
        $files = [$this->file('src/A.php'), $this->file('tests/A.php')];

        $filtered = ScanPathFilter::apply($files, ['./src']);

        self::assertSame([$files[0]], $filtered);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_a_bare_dot_scan_path_is_dropped_and_treated_as_no_filter(): void
    {
        $files = [$this->file('src/A.php'), $this->file('tests/A.php')];

        self::assertSame($files, ScanPathFilter::apply($files, ['.']));
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_normalizes_windows_separators_in_project_files(): void
    {
        $projectFile = ProjectFile::create('apps\\api\\src\\A.php', '/app/apps/api/src/A.php', '<?php');

        $filtered = ScanPathFilter::apply([$projectFile], ['apps/api']);

        self::assertSame([$projectFile], $filtered);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_returns_empty_when_no_file_matches(): void
    {
        $filtered = ScanPathFilter::apply([$this->file('src/A.php')], ['apps/api']);

        self::assertSame([], $filtered);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_blank_entries_do_not_short_circuit_subsequent_scan_paths(): void
    {
        $projectFile = $this->file('apps/api/src/A.php');
        $dropped = $this->file('apps/web/src/B.php');

        $filtered = ScanPathFilter::apply([$projectFile, $dropped], ['', 'apps/api']);

        self::assertSame([$projectFile], $filtered);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_backslashes_in_scan_path_are_normalized_to_forward_slashes(): void
    {
        $projectFile = $this->file('apps/api/src/A.php');

        $filtered = ScanPathFilter::apply([$projectFile], ['apps\\api']);

        self::assertSame([$projectFile], $filtered);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_file_matching_multiple_scan_paths_is_added_only_once(): void
    {
        $file = $this->file('apps/api/src/A.php');

        $filtered = ScanPathFilter::apply([$file], ['apps/api', 'apps/api/src']);

        self::assertCount(1, $filtered);
    }

    /**
     * @throws InvalidProjectFileException
     */
    private function file(string $relativePath): ProjectFile
    {
        return ProjectFile::create($relativePath, '/abs/'.$relativePath, '<?php');
    }
}
