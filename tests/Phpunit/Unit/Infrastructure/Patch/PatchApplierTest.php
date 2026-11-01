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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Patch;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Patch\DiffHunk;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Patch\FilePatch;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Patch\PatchApplier;

final class PatchApplierTest extends TestCase
{
    public function test_it_replaces_the_lines_a_hunk_expects_where_it_says(): void
    {
        $filePatch = new FilePatch('x.php', [new DiffHunk(2, ['b', 'c'], ['b', 'C'])]);

        self::assertSame("a\nb\nC\nd\n", (new PatchApplier())->apply("a\nb\nc\nd\n", $filePatch));
    }

    #[DataProvider('appliedPatches')]
    public function test_it_applies_a_patch_the_file_still_takes(string $content, FilePatch $filePatch, string $expected): void
    {
        self::assertSame($expected, (new PatchApplier())->apply($content, $filePatch));
    }

    /**
     * @return iterable<string, array{string, FilePatch, string}>
     */
    public static function appliedPatches(): iterable
    {
        yield 'lines moved since the audit' => ["new\na\nb\nc\n", new FilePatch('x.php', [new DiffHunk(2, ['b'], ['B'])]), "new\na\nB\nc\n"];
        yield 'windows line endings' => ["a\r\nb\r\n", new FilePatch('x.php', [new DiffHunk(2, ['b'], ['B', 'C'])]), "a\r\nB\r\nC\r\n"];
        yield 'no newline at the end' => ["a\nb", new FilePatch('x.php', [new DiffHunk(2, ['b'], ['B'])]), "a\nB"];
        yield 'lines added before line 2' => ["a\nb\n", new FilePatch('x.php', [new DiffHunk(2, [], ['new'])]), "a\nnew\nb\n"];
        yield 'lines added at the end' => ["a\n", new FilePatch('x.php', [new DiffHunk(2, [], ['new'])]), "a\nnew\n"];
        yield 'a later hunk shifted by an earlier one' => ["a\nb\nc\nb\n", new FilePatch('x.php', [new DiffHunk(1, ['a'], ['a', 'a2']), new DiffHunk(4, ['b'], ['B'])]), "a\na2\nb\nc\nB\n"];
    }

    #[DataProvider('patchesThatNoLongerApply')]
    public function test_a_patch_that_no_longer_applies_cleanly_leaves_the_file_alone(string $content, FilePatch $filePatch): void
    {
        self::assertNull((new PatchApplier())->apply($content, $filePatch));
    }

    /**
     * @return iterable<string, array{string, FilePatch}>
     */
    public static function patchesThatNoLongerApply(): iterable
    {
        yield 'lines no longer there' => ["a\nb\n", new FilePatch('x.php', [new DiffHunk(2, ['c'], ['C'])])];
        yield 'lines moved to two places' => ["x\nb\ny\nb\n", new FilePatch('x.php', [new DiffHunk(1, ['b'], ['B'])])];
        yield 'lines added past the end' => ["a\n", new FilePatch('x.php', [new DiffHunk(5, [], ['new'])])];
        yield 'a second hunk that does not apply' => ["a\nb\n", new FilePatch('x.php', [new DiffHunk(1, ['a'], ['A']), new DiffHunk(2, ['z'], ['Z'])])];
        yield 'lines past the end of the file' => ["a\n", new FilePatch('x.php', [new DiffHunk(1, ['a', 'b'], ['A'])])];
    }
}
