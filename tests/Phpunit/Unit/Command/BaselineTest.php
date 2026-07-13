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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AcceptedFindingFeedback;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Baseline;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\MalformedBaselineFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\UnsafeBaselineWriteException;

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
     * @throws UnsafeBaselineWriteException
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
     * @throws UnsafeBaselineWriteException
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
     * A hand-edited or merged baseline file could carry a redundant
     * `attacker_fingerprint` equal to its own `fingerprint` — the tool's own
     * writer never produces this (`BaselineProcessor::entryFor()` only sets
     * `attacker_fingerprint` when it differs), but `load()` must not grant a
     * count-aware budget of 2 credits for what is really just 1 accepted
     * occurrence.
     *
     * @throws MalformedBaselineFileException
     * @throws UnsafeBaselineWriteException
     */
    public function test_load_does_not_double_count_a_redundant_attacker_fingerprint_equal_to_its_own_fingerprint(): void
    {
        $path = $this->tmpDir.'/baseline.json';
        $baseline = new Baseline($this->filesystem);

        $baseline->save($path, [
            [...$this->entry('SSA-SAME'), 'attacker_fingerprint' => 'SSA-SAME'],
        ]);

        self::assertSame(['SSA-SAME'], $baseline->load($path));
    }

    /**
     * @throws MalformedBaselineFileException
     * @throws UnsafeBaselineWriteException
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
     * @throws UnsafeBaselineWriteException
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
     * @throws UnsafeBaselineWriteException
     */
    public function test_save_wraps_an_encoding_failure_as_a_malformed_baseline_file_exception(): void
    {
        $path = $this->tmpDir.'/baseline.json';

        $this->expectException(MalformedBaselineFileException::class);

        (new Baseline($this->filesystem))->save($path, [[...$this->entry('SSA-AAA'), 'title' => "Bad\xFFTitle"]]);
    }

    /**
     * @throws MalformedBaselineFileException
     * @throws UnsafeBaselineWriteException
     */
    public function test_save_refuses_to_write_through_a_symlinked_baseline_file(): void
    {
        $path = $this->tmpDir.'/baseline.json';
        $outsideTarget = sys_get_temp_dir().'/baseline_symlink_target_'.uniqid('', true);
        $this->filesystem->dumpFile($outsideTarget, 'ORIGINAL');
        symlink($outsideTarget, $path);

        try {
            $this->expectException(UnsafeBaselineWriteException::class);

            (new Baseline($this->filesystem))->save($path, [$this->entry('SSA-AAA')]);
        } finally {
            self::assertSame('ORIGINAL', file_get_contents($outsideTarget));
            $this->filesystem->remove($outsideTarget);
        }
    }

    /**
     * @throws MalformedBaselineFileException
     * @throws UnsafeBaselineWriteException
     */
    public function test_save_refuses_to_write_through_a_symlinked_parent_directory(): void
    {
        $outsideDir = sys_get_temp_dir().'/baseline_symlink_dir_'.uniqid('', true);
        $this->filesystem->mkdir($outsideDir);
        $nestedDir = $this->tmpDir.'/nested';
        symlink($outsideDir, $nestedDir);

        try {
            $this->expectException(UnsafeBaselineWriteException::class);

            (new Baseline($this->filesystem))->save($nestedDir.'/baseline.json', [$this->entry('SSA-AAA')]);
        } finally {
            self::assertSame([], glob($outsideDir.'/*'));
            $this->filesystem->remove($outsideDir);
        }
    }

    /**
     * @throws MalformedBaselineFileException
     */
    public function test_feedback_is_empty_for_a_missing_file(): void
    {
        self::assertTrue((new Baseline($this->filesystem))->feedback($this->tmpDir.'/absent.json')->isEmpty());
    }

    /**
     * @throws MalformedBaselineFileException
     */
    public function test_feedback_collects_entries_annotated_with_a_reason(): void
    {
        $path = $this->tmpDir.'/baseline.json';
        $entry = $this->entry('SSA-AAA');
        $entry['reason'] = 'Query goes through SafeQuery, parameterized upstream.';
        $this->filesystem->dumpFile($path, json_encode([$entry, $this->entry('SSA-BBB')], \JSON_THROW_ON_ERROR));

        $reviewerFeedback = (new Baseline($this->filesystem))->feedback($path);

        self::assertEquals(
            [new AcceptedFindingFeedback('sql_injection', 'src/Foo.php', 'Test Vuln', 'Query goes through SafeQuery, parameterized upstream.')],
            $reviewerFeedback->entries,
        );
    }

    /**
     * @throws MalformedBaselineFileException
     */
    public function test_feedback_skips_a_blank_or_non_string_reason_and_plain_string_entries(): void
    {
        $path = $this->tmpDir.'/baseline.json';
        $blankReason = $this->entry('SSA-AAA');
        $blankReason['reason'] = '   ';
        $nonStringReason = $this->entry('SSA-BBB');
        $nonStringReason['reason'] = 42;
        $this->filesystem->dumpFile($path, json_encode([$blankReason, $nonStringReason, 'SSA-CCC'], \JSON_THROW_ON_ERROR));

        self::assertTrue((new Baseline($this->filesystem))->feedback($path)->isEmpty());
    }

    /**
     * @throws MalformedBaselineFileException
     */
    public function test_feedback_defaults_missing_metadata_fields_to_empty_strings(): void
    {
        $path = $this->tmpDir.'/baseline.json';
        $this->filesystem->dumpFile($path, json_encode([['fingerprint' => 'SSA-AAA', 'reason' => 'accepted risk']], \JSON_THROW_ON_ERROR));

        $reviewerFeedback = (new Baseline($this->filesystem))->feedback($path);

        self::assertEquals([new AcceptedFindingFeedback('', '', '', 'accepted risk')], $reviewerFeedback->entries);
    }

    /**
     * @throws MalformedBaselineFileException
     */
    public function test_feedback_throws_when_the_file_is_not_valid_json(): void
    {
        $path = $this->tmpDir.'/baseline.json';
        $this->filesystem->dumpFile($path, '{not json');

        $this->expectException(MalformedBaselineFileException::class);

        (new Baseline($this->filesystem))->feedback($path);
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
