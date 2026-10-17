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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Config;

use Override;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\MalformedProjectConfigException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandaloneConfigFileReader;

final class StandaloneConfigFileReaderTest extends TestCase
{
    private const string ALIAS_BOMB = <<<'YAML'
        a0: &a0 [x, x, x, x, x, x, x, x, x, x]
        a1: &a1 [*a0, *a0, *a0, *a0, *a0, *a0, *a0, *a0, *a0, *a0]
        a2: &a2 [*a1, *a1, *a1, *a1, *a1, *a1, *a1, *a1, *a1, *a1]
        a3: &a3 [*a2, *a2, *a2, *a2, *a2, *a2, *a2, *a2, *a2, *a2]
        a4: &a4 [*a3, *a3, *a3, *a3, *a3, *a3, *a3, *a3, *a3, *a3]
        a5: &a5 [*a4, *a4, *a4, *a4, *a4, *a4, *a4, *a4, *a4, *a4]
        a6: &a6 [*a5, *a5, *a5, *a5, *a5, *a5, *a5, *a5, *a5, *a5]
        a7: &a7 [*a6, *a6, *a6, *a6, *a6, *a6, *a6, *a6, *a6, *a6]
        a8: &a8 [*a7, *a7, *a7, *a7, *a7, *a7, *a7, *a7, *a7, *a7]
        scan: {included_paths: *a8}

        YAML;

    private string $configFile;

    private Filesystem $filesystem;

    #[Override]
    protected function setUp(): void
    {
        $this->filesystem = new Filesystem();
        $this->configFile = sys_get_temp_dir().'/ssa-config-file-'.bin2hex(random_bytes(6)).'/.symfony-security-auditor.yaml';
    }

    #[Override]
    protected function tearDown(): void
    {
        $this->filesystem->remove(\dirname($this->configFile));
    }

    /**
     * @throws MalformedProjectConfigException
     */
    public function test_a_file_whose_aliases_expand_past_any_configuration_is_refused_before_it_is_walked(): void
    {
        $this->filesystem->dumpFile($this->configFile, self::ALIAS_BOMB);

        $this->expectException(MalformedProjectConfigException::class);
        $this->expectExceptionMessage(\sprintf('Config file "%s" holds 10000 values or more once its YAML aliases are expanded', $this->configFile));

        (new StandaloneConfigFileReader())->read($this->configFile);
    }

    /**
     * @throws MalformedProjectConfigException
     */
    public function test_a_file_holding_one_value_short_of_the_limit_is_read(): void
    {
        $this->writeExcludedPaths(9997);

        self::assertCount(9997, $this->excludedPathsRead());
    }

    /**
     * @throws MalformedProjectConfigException
     */
    public function test_a_file_reaching_the_limit_is_refused(): void
    {
        $this->writeExcludedPaths(9998);

        $this->expectException(MalformedProjectConfigException::class);

        (new StandaloneConfigFileReader())->read($this->configFile);
    }

    /**
     * @throws MalformedProjectConfigException
     */
    public function test_an_alias_that_merely_repeats_a_value_is_still_read(): void
    {
        $this->filesystem->dumpFile($this->configFile, "scan:\n    included_paths: &paths [src, config]\n    excluded_paths: *paths\n");

        self::assertSame(
            ['scan' => ['included_paths' => ['src', 'config'], 'excluded_paths' => ['src', 'config']]],
            (new StandaloneConfigFileReader())->read($this->configFile),
        );
    }

    /**
     * @throws MalformedProjectConfigException
     */
    public function test_a_file_of_half_a_mebibyte_is_read(): void
    {
        $this->filesystem->dumpFile($this->configFile, $this->paddedTo(524_288));

        self::assertSame(['profile' => 'fast'], (new StandaloneConfigFileReader())->read($this->configFile));
    }

    /**
     * @throws MalformedProjectConfigException
     */
    public function test_a_file_one_byte_past_half_a_mebibyte_is_refused_before_it_is_parsed(): void
    {
        $this->filesystem->dumpFile($this->configFile, $this->paddedTo(524_289));

        $this->expectException(MalformedProjectConfigException::class);
        $this->expectExceptionMessage(\sprintf('Config file "%s" is larger than 524288 bytes, far more than any configuration needs, so it was not parsed.', $this->configFile));

        (new StandaloneConfigFileReader())->read($this->configFile);
    }

    /**
     * @throws MalformedProjectConfigException
     */
    public function test_a_file_nested_thirty_two_levels_deep_is_read(): void
    {
        $this->filesystem->dumpFile($this->configFile, self::nestedTo(32));

        self::assertSame(self::nestedValueTo(32), (new StandaloneConfigFileReader())->read($this->configFile));
    }

    /**
     * @throws MalformedProjectConfigException
     */
    public function test_a_file_nested_thirty_three_levels_deep_is_refused_before_it_is_parsed(): void
    {
        $this->filesystem->dumpFile($this->configFile, self::nestedTo(33)."profile: fast\n");

        $this->expectException(MalformedProjectConfigException::class);
        $this->expectExceptionMessage(\sprintf('Config file "%s" nests more than 32 levels deep, far more than any configuration needs, so it was not parsed.', $this->configFile));

        (new StandaloneConfigFileReader())->read($this->configFile);
    }

    /**
     * @throws MalformedProjectConfigException
     */
    public function test_comments_between_its_levels_do_not_hide_how_deep_a_file_nests(): void
    {
        $this->filesystem->dumpFile($this->configFile, str_replace("a:\n", "a:\n# note\n\n", self::nestedTo(33)));

        $this->expectException(MalformedProjectConfigException::class);
        $this->expectExceptionMessage('nests more than 32 levels deep');

        (new StandaloneConfigFileReader())->read($this->configFile);
    }

    /**
     * @throws MalformedProjectConfigException
     */
    #[DataProvider('filesNestedPastTheLimitOnTheLineOfAParent')]
    public function test_a_file_nesting_past_the_limit_on_the_line_of_a_parent_is_refused_before_it_is_parsed(string $yaml): void
    {
        $this->filesystem->dumpFile($this->configFile, $yaml);

        $this->expectException(MalformedProjectConfigException::class);
        $this->expectExceptionMessage(\sprintf('Config file "%s" nests more than 32 levels deep, far more than any configuration needs, so it was not parsed.', $this->configFile));

        (new StandaloneConfigFileReader())->read($this->configFile);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function filesNestedPastTheLimitOnTheLineOfAParent(): iterable
    {
        yield 'compact block sequences' => [str_repeat('- ', 33)."item\n"];
        yield 'compact mappings inside sequences' => [str_repeat('- key: ', 17)."item\n"];
        yield 'complex-key markers' => [str_repeat('? ', 33)."key\n"];
        yield 'merge keys holding sequences' => ["base:\n    ".str_repeat('<<: - ', 16)."item\n"];
        yield 'quoted keys' => [str_repeat('"key": ', 33)."item\n"];
        yield 'anchors and tags between the markers' => [str_repeat('- &node !!seq ', 33)."item\n"];
        yield 'markers separated by tabs' => [str_repeat("-\t", 33)."item\n"];
        yield 'compact levels on top of indented ones' => [self::nestedTo(20, 'a', str_repeat('- ', 14)."item\n")];
        yield 'compact levels in a file with Windows line endings' => [str_replace("\n", "\r\n", self::nestedTo(30, 'a', "- - - - item\n"))];
        yield 'indented levels in a file breaking its lines with carriage returns alone' => [str_replace("\n", "\r", self::nestedTo(33))];
        yield 'block sequences in a file breaking its lines with carriage returns alone' => [implode('', array_map(static fn (int $level): string => str_repeat(' ', $level)."-\r", range(0, 32)))];
    }

    /**
     * @param array<array-key, mixed> $expected
     *
     * @throws MalformedProjectConfigException
     */
    #[DataProvider('filesNestedToTheLimitOnTheLineOfAParent')]
    public function test_a_file_nesting_to_the_limit_on_the_line_of_a_parent_is_read(string $yaml, array $expected): void
    {
        $this->filesystem->dumpFile($this->configFile, $yaml);

        self::assertSame($expected, (new StandaloneConfigFileReader())->read($this->configFile));
    }

    /**
     * @return iterable<string, array{string, array<array-key, mixed>}>
     */
    public static function filesNestedToTheLimitOnTheLineOfAParent(): iterable
    {
        yield 'compact block sequences' => [str_repeat('- ', 32)."item\n", self::listedTo(32)];
        yield 'compact levels on top of indented ones' => [self::nestedTo(20, 'a', str_repeat('- ', 13)."item\n"), self::nestedValueTo(20, 'a', self::listedTo(13))];
        yield 'a line closing the compact levels before it' => [str_repeat('- ', 32)."item\n".str_repeat('- ', 32)."item\n", [...self::listedTo(32), ...self::listedTo(32)]];
        yield 'a flow sequence holding a mapping' => [self::nestedTo(32, 'a', "leaf: [{k: v}]\n"), self::nestedValueTo(32, 'a', ['leaf' => [['k' => 'v']]])];
        yield 'a flow mapping' => [self::nestedTo(32, 'a', "leaf: {k: v}\n"), self::nestedValueTo(32, 'a', ['leaf' => ['k' => 'v']])];
        yield 'a comment after a key' => [self::nestedTo(32, 'a', "leaf: # note: none\n"), self::nestedValueTo(32, 'a', ['leaf' => null])];
    }

    /**
     * @throws MalformedProjectConfigException
     */
    public function test_a_file_nesting_a_long_line_under_compact_levels_is_refused_before_the_parser_copies_it_once_per_level(): void
    {
        $this->filesystem->dumpFile($this->configFile, "scan:\n    included_paths:\n        ".str_repeat('- ', 28).str_repeat('s', 160_000)."\n");

        memory_reset_peak_usage();
        $memoryBefore = memory_get_usage();
        $refusal = $this->refusalOf($this->configFile);
        $peakMegabytes = (memory_get_peak_usage() - $memoryBefore) / 1_048_576;

        self::assertSame(\sprintf('Config file "%s" nests more of its content than any configuration needs: its lines, each counted once for every level it sits in, add up to more than 4194304 bytes, so it was not parsed.', $this->configFile), $refusal);
        self::assertLessThan(8, $peakMegabytes);
    }

    /**
     * @throws MalformedProjectConfigException
     */
    public function test_a_file_whose_lines_counted_once_per_level_add_up_to_the_limit_is_read(): void
    {
        $this->filesystem->dumpFile($this->configFile, $this->fileNestingExactly(4_194_304));

        self::assertSame([str_repeat('k', 17) => self::nestedValueTo(32, 'a', null)], (new StandaloneConfigFileReader())->read($this->configFile));
    }

    /**
     * @throws MalformedProjectConfigException
     */
    public function test_a_file_whose_lines_counted_once_per_level_add_up_past_the_limit_is_refused_before_it_is_parsed(): void
    {
        $this->filesystem->dumpFile($this->configFile, $this->fileNestingExactly(4_194_305));

        $this->expectException(MalformedProjectConfigException::class);
        $this->expectExceptionMessage('add up to more than 4194304 bytes, so it was not parsed.');

        (new StandaloneConfigFileReader())->read($this->configFile);
    }

    /**
     * @param array<array-key, mixed> $expected
     *
     * @throws MalformedProjectConfigException
     */
    #[DataProvider('shallowFilesWithManyLines')]
    public function test_lines_that_open_no_level_do_not_count_towards_the_depth(string $yaml, array $expected): void
    {
        $this->filesystem->dumpFile($this->configFile, $yaml);

        self::assertSame($expected, (new StandaloneConfigFileReader())->read($this->configFile));
    }

    /**
     * @return iterable<string, array{string, array<array-key, mixed>}>
     */
    public static function shallowFilesWithManyLines(): iterable
    {
        $paths = array_map(static fn (int $length): string => str_repeat('p', $length), range(1, 40));

        yield 'forty siblings each longer than the one before' => ["scan:\n    excluded_paths:\n".implode('', array_map(static fn (string $path): string => \sprintf("        - %s\n", $path), $paths)), ['scan' => ['excluded_paths' => $paths]]];
        yield 'forty comments each indented one more' => [implode('', array_map(static fn (int $indent): string => str_repeat(' ', $indent)."# note\n", range(0, 39)))."profile: fast\n", ['profile' => 'fast']];
        yield 'forty blank lines each indented one more, with Windows line endings' => ["profile: fast\r\n".implode('', array_map(static fn (int $indent): string => str_repeat(' ', $indent)."\r\n", range(1, 40)))."model: gpt\r\n", ['profile' => 'fast', 'model' => 'gpt']];
        yield 'two branches of twenty levels' => [self::nestedTo(20).self::nestedTo(20, 'b'), [...self::nestedValueTo(20), ...self::nestedValueTo(20, 'b')]];
    }

    /**
     * @throws MalformedProjectConfigException
     */
    public function test_a_missing_file_reads_as_empty(): void
    {
        self::assertSame([], (new StandaloneConfigFileReader())->read($this->configFile));
    }

    private static function nestedTo(int $levels, string $key = 'a', string $leaf = "leaf: 1\n"): string
    {
        $yaml = '';
        for ($level = 0; $level < $levels - 1; ++$level) {
            $yaml .= str_repeat(' ', $level).$key.":\n";
        }

        return $yaml.str_repeat(' ', $levels - 1).$leaf;
    }

    /**
     * @return array<string, mixed>
     */
    private static function nestedValueTo(int $levels, string $key = 'a', mixed $leaf = ['leaf' => 1]): array
    {
        $value = [$key => $leaf];
        for ($level = 2; $level < $levels; ++$level) {
            $value = [$key => $value];
        }

        return $value;
    }

    /**
     * @return list<mixed>
     */
    private static function listedTo(int $levels): array
    {
        $value = ['item'];
        for ($level = 1; $level < $levels; ++$level) {
            $value = [$value];
        }

        return $value;
    }

    private function fileNestingExactly(int $nestedBytes): string
    {
        $chainBytes = 13_615;
        $keyLength = (($nestedBytes - $chainBytes - 1) % 32) + 1;
        $commentLength = intdiv($nestedBytes - $chainBytes - $keyLength, 32);

        $yaml = str_repeat('k', $keyLength).":\n";
        for ($level = 1; $level < 32; ++$level) {
            $yaml .= str_repeat(' ', $level)."a:\n";
        }

        return $yaml.str_repeat(' ', 32).'#'.str_repeat('x', $commentLength)."\n";
    }

    private function refusalOf(string $configFile): ?string
    {
        try {
            (new StandaloneConfigFileReader())->read($configFile);
        } catch (MalformedProjectConfigException $malformedProjectConfigException) {
            return $malformedProjectConfigException->getMessage();
        }

        return null;
    }

    private function paddedTo(int $bytes): string
    {
        $yaml = "profile: fast\n#";

        return $yaml.str_repeat('x', $bytes - \strlen($yaml));
    }

    private function writeExcludedPaths(int $count): void
    {
        $this->filesystem->dumpFile(
            $this->configFile,
            \sprintf("scan:\n    excluded_paths:\n%s", implode('', array_map(static fn (int $index): string => \sprintf("        - path%d\n", $index), range(1, $count)))),
        );
    }

    /**
     * @return array<array-key, mixed>
     *
     * @throws MalformedProjectConfigException
     */
    private function excludedPathsRead(): array
    {
        $scan = (new StandaloneConfigFileReader())->read($this->configFile)['scan'] ?? null;
        $excludedPaths = \is_array($scan) ? ($scan['excluded_paths'] ?? null) : null;

        return \is_array($excludedPaths) ? $excludedPaths : [];
    }
}
