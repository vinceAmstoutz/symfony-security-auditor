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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Command;

use Override;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Baseline;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\MalformedBaselineFileException;

final class BaselineTest extends TestCase
{
    private Filesystem $filesystem;

    private string $tmpDir;

    #[Override]
    protected function setUp(): void
    {
        $this->filesystem = new Filesystem();
        $this->tmpDir = sys_get_temp_dir().'/baseline_test_'.uniqid('', true);
        $this->filesystem->mkdir($this->tmpDir);
    }

    #[Override]
    protected function tearDown(): void
    {
        $this->filesystem->remove($this->tmpDir);
    }

    /**
     * @throws MalformedBaselineFileException
     */
    public function test_load_returns_empty_list_for_a_missing_file(): void
    {
        self::assertSame([], (new Baseline($this->filesystem))->load($this->tmpDir.'/absent.json'));
    }

    /**
     * @throws MalformedBaselineFileException
     */
    public function test_save_then_load_round_trips_the_fingerprints(): void
    {
        $path = $this->tmpDir.'/baseline.json';
        $baseline = new Baseline($this->filesystem);

        $baseline->save($path, [
            $this->entry('SSA-AAA'),
            $this->entry('SSA-BBB'),
        ]);

        self::assertSame(['SSA-AAA', 'SSA-BBB'], $baseline->load($path));
    }

    /**
     * @throws MalformedBaselineFileException
     */
    public function test_load_also_accepts_the_attacker_fingerprint_of_a_type_corrected_entry(): void
    {
        $path = $this->tmpDir.'/baseline.json';
        $baseline = new Baseline($this->filesystem);

        $baseline->save($path, [
            [...$this->entry('SSA-CORRECTED'), 'attacker_fingerprint' => 'SSA-ORIGINAL'],
            $this->entry('SSA-PLAIN'),
        ]);

        self::assertSame(['SSA-CORRECTED', 'SSA-ORIGINAL', 'SSA-PLAIN'], $baseline->load($path));
    }

    /**
     * @throws MalformedBaselineFileException
     */
    public function test_save_writes_pretty_printed_json(): void
    {
        $path = $this->tmpDir.'/baseline.json';

        (new Baseline($this->filesystem))->save($path, [$this->entry('SSA-AAA')]);

        $contents = file_get_contents($path);
        self::assertIsString($contents);
        self::assertStringContainsString("[\n", $contents);
        self::assertStringContainsString('"fingerprint": "SSA-AAA"', $contents);
        self::assertStringContainsString('"file": "src/Foo.php"', $contents);
        self::assertStringStartsWith('[', $contents);
        self::assertStringEndsWith(']'.\PHP_EOL, $contents);
    }

    /**
     * @throws MalformedBaselineFileException
     */
    public function test_load_throws_when_the_file_is_not_valid_json(): void
    {
        $path = $this->tmpDir.'/broken.json';
        $this->filesystem->dumpFile($path, '{not json');

        $this->expectException(MalformedBaselineFileException::class);

        (new Baseline($this->filesystem))->load($path);
    }

    /**
     * @throws MalformedBaselineFileException
     */
    public function test_load_throws_when_the_json_is_a_bare_scalar(): void
    {
        $path = $this->tmpDir.'/scalar.json';
        $this->filesystem->dumpFile($path, '42');

        $this->expectException(MalformedBaselineFileException::class);

        (new Baseline($this->filesystem))->load($path);
    }

    /**
     * @throws MalformedBaselineFileException
     */
    public function test_load_throws_when_the_json_is_an_object_of_non_string_entries(): void
    {
        $path = $this->tmpDir.'/object.json';
        $this->filesystem->dumpFile($path, '{"a": 1}');

        $this->expectException(MalformedBaselineFileException::class);

        (new Baseline($this->filesystem))->load($path);
    }

    /**
     * @throws MalformedBaselineFileException
     */
    public function test_load_throws_when_the_json_is_a_bare_object_of_string_values(): void
    {
        $path = $this->tmpDir.'/bare-object.json';
        $this->filesystem->dumpFile($path, '{"type": "sql_injection", "file": "src/Foo.php"}');

        $this->expectException(MalformedBaselineFileException::class);

        (new Baseline($this->filesystem))->load($path);
    }

    /**
     * @throws MalformedBaselineFileException
     */
    public function test_load_throws_when_an_entry_is_not_a_string(): void
    {
        $path = $this->tmpDir.'/mixed.json';
        $this->filesystem->dumpFile($path, '["SSA-AAA", 42]');

        $this->expectException(MalformedBaselineFileException::class);

        (new Baseline($this->filesystem))->load($path);
    }

    /**
     * @throws MalformedBaselineFileException
     */
    public function test_load_reads_the_legacy_flat_fingerprint_array(): void
    {
        $path = $this->tmpDir.'/legacy.json';
        $this->filesystem->dumpFile($path, '["SSA-AAA", "SSA-BBB"]');

        self::assertSame(['SSA-AAA', 'SSA-BBB'], (new Baseline($this->filesystem))->load($path));
    }

    /**
     * @throws MalformedBaselineFileException
     */
    public function test_load_mixes_legacy_string_and_rich_object_entries(): void
    {
        $path = $this->tmpDir.'/mixed-format.json';
        $this->filesystem->dumpFile($path, '["SSA-AAA", {"fingerprint": "SSA-BBB", "title": "X"}]');

        self::assertSame(['SSA-AAA', 'SSA-BBB'], (new Baseline($this->filesystem))->load($path));
    }

    /**
     * @throws MalformedBaselineFileException
     */
    public function test_load_throws_when_an_entry_object_has_no_fingerprint(): void
    {
        $path = $this->tmpDir.'/no-fingerprint.json';
        $this->filesystem->dumpFile($path, '[{"title": "X"}]');

        $this->expectException(MalformedBaselineFileException::class);

        (new Baseline($this->filesystem))->load($path);
    }

    /**
     * @throws MalformedBaselineFileException
     */
    public function test_load_wraps_an_io_failure_as_a_malformed_baseline_file_exception(): void
    {
        $path = $this->tmpDir.'/unreadable-dir';
        $this->filesystem->mkdir($path);

        $this->expectException(MalformedBaselineFileException::class);

        (new Baseline($this->filesystem))->load($path);
    }

    /**
     * @throws MalformedBaselineFileException
     */
    public function test_save_wraps_an_io_failure_as_a_malformed_baseline_file_exception(): void
    {
        $blockingFile = $this->tmpDir.'/not-a-directory';
        $this->filesystem->dumpFile($blockingFile, 'x');

        $this->expectException(MalformedBaselineFileException::class);

        (new Baseline($this->filesystem))->save($blockingFile.'/baseline.json', [$this->entry('SSA-AAA')]);
    }

    /**
     * @throws MalformedBaselineFileException
     */
    public function test_save_wraps_an_encoding_failure_as_a_malformed_baseline_file_exception(): void
    {
        $path = $this->tmpDir.'/baseline.json';

        $this->expectException(MalformedBaselineFileException::class);

        (new Baseline($this->filesystem))->save($path, [[...$this->entry('SSA-AAA'), 'title' => "Bad\xFFTitle"]]);
    }

    /**
     * @return array<string, string>
     */
    private function entry(string $fingerprint): array
    {
        return [
            'fingerprint' => $fingerprint,
            'type' => 'sql_injection',
            'file' => 'src/Foo.php',
            'title' => 'Test Vuln',
            'added_at' => '2026-07-03',
        ];
    }
}
