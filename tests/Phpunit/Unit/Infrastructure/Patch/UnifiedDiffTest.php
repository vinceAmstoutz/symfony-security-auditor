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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Patch\UnifiedDiff;

final class UnifiedDiffTest extends TestCase
{
    public function test_it_reads_the_hunk_of_a_fenced_patch(): void
    {
        $patch = <<<'DIFF'
            ```diff
            --- a/src/Controller/UserController.php
            +++ b/src/Controller/UserController.php
            @@ -3,3 +3,3 @@
             $id = $request->get('id');
            -$sql = "SELECT * FROM user WHERE id = $id";
            +$sql = 'SELECT * FROM user WHERE id = ?';
             return $sql;
            ```
            DIFF;

        self::assertEquals(
            [new FilePatch('src/Controller/UserController.php', [new DiffHunk(
                3,
                ['$id = $request->get(\'id\');', '$sql = "SELECT * FROM user WHERE id = $id";', 'return $sql;'],
                ['$id = $request->get(\'id\');', '$sql = \'SELECT * FROM user WHERE id = ?\';', 'return $sql;'],
            )])],
            UnifiedDiff::parse($patch)?->filePatches,
        );
    }

    #[DataProvider('patchesThatDoNotRead')]
    public function test_a_patch_that_does_not_read_as_one_is_none(string $patch): void
    {
        self::assertNull(UnifiedDiff::parse($patch));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function patchesThatDoNotRead(): iterable
    {
        yield 'a hunk shorter than its header says' => ["--- a/x.php\n+++ b/x.php\n@@ -1,3 +1,3 @@\n a\n-b\n+c"];
        yield 'a file it creates' => ["--- /dev/null\n+++ b/x.php\n@@ -0,0 +1 @@\n+a"];
        yield 'a file it deletes' => ["--- a/x.php\n+++ /dev/null\n@@ -1 +0,0 @@\n-a"];
        yield 'a file it renames' => ["--- a/x.php\n+++ b/y.php\n@@ -1 +1 @@\n-a\n+b"];
        yield 'a header with no hunk' => ["--- a/x.php\n+++ b/x.php\nnothing to change"];
        yield 'a second file with a broken hunk' => ["--- a/x.php\n+++ b/x.php\n@@ -1 +1 @@\n-a\n+b\n--- a/y.php\n+++ b/y.php\n@@ -1,2 +1 @@\n-a"];
        yield 'a path that climbs out of the project' => ["--- a/../x.php\n+++ b/../x.php\n@@ -1 +1 @@\n-a\n+b"];
        yield 'an absolute path' => ["--- a//etc/x.php\n+++ b//etc/x.php\n@@ -1 +1 @@\n-a\n+b"];
        yield 'a windows drive path' => ["--- a/C:/x.php\n+++ b/C:/x.php\n@@ -1 +1 @@\n-a\n+b"];
        yield 'a backslash path that climbs out' => ["--- a/src\\..\\..\\x.php\n+++ b/src\\..\\..\\x.php\n@@ -1 +1 @@\n-a\n+b"];
        yield 'no patch at all' => ['NO_FIX: the code is fine'];
        yield 'prose inside a hunk' => ["--- a/x.php\n+++ b/x.php\n@@ -1,2 +1,2 @@\n a\nThen change b:\n-b\n+c"];
    }

    /**
     * @param list<FilePatch> $expected
     */
    #[DataProvider('patchShapes')]
    public function test_it_reads_each_file_and_hunk_of_a_patch(string $patch, array $expected): void
    {
        self::assertEquals($expected, UnifiedDiff::parse($patch)?->filePatches);
    }

    /**
     * @return iterable<string, array{string, list<FilePatch>}>
     */
    public static function patchShapes(): iterable
    {
        yield 'two files, two hunks' => [
            "--- a/x.php\n+++ b/x.php\n@@ -1,2 +1,2 @@\n-a\n+b\n c\n@@ -9 +9 @@\n-d\n+e\n--- a/y.php\n+++ b/y.php\n@@ -4 +4 @@\n-f\n+g",
            [
                new FilePatch('x.php', [new DiffHunk(1, ['a', 'c'], ['b', 'c']), new DiffHunk(9, ['d'], ['e'])]),
                new FilePatch('y.php', [new DiffHunk(4, ['f'], ['g'])]),
            ],
        ];
        yield 'lines added after line 2' => ["--- a/x.php\n+++ b/x.php\n@@ -2,0 +3,2 @@\n+a\n+b", [new FilePatch('x.php', [new DiffHunk(3, [], ['a', 'b'])])]];
        yield 'an empty context line written without its space' => ["--- a/x.php\n+++ b/x.php\n@@ -1,3 +1,3 @@\n-a\n+b\n\n c", [new FilePatch('x.php', [new DiffHunk(1, ['a', '', 'c'], ['b', '', 'c'])])]];
        yield 'a last line with no newline' => ["--- a/x.php\n+++ b/x.php\n@@ -1 +1 @@\n-a\n\\ No newline at end of file\n+b\n\\ No newline at end of file", [new FilePatch('x.php', [new DiffHunk(1, ['a'], ['b'])])]];
        yield 'windows line endings and a dated header' => ["--- a/x.php\t2026-11-01\r\n+++ b/x.php\t2026-11-01\r\n@@ -1 +1 @@\r\n-a\r\n+b\r\n", [new FilePatch('x.php', [new DiffHunk(1, ['a'], ['b'])])]];
    }
}
