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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Scan\PathText;

final class PathTextTest extends TestCase
{
    #[DataProvider('trimmedPaths')]
    public function test_it_trims_a_path_the_way_its_encoding_allows(string $path, string $expected): void
    {
        self::assertSame($expected, PathText::of($path)->trim()->toString());
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function trimmedPaths(): iterable
    {
        yield 'ascii whitespace around valid text' => [" \t src/café \n", 'src/café'];
        yield 'no-break space and byte order mark around valid text' => ["\u{A0}src\u{FEFF}", 'src'];
        yield 'a decomposed accent in valid text is composed' => ["cafe\u{0301}", "caf\u{E9}"];
        yield 'ascii whitespace around text that is not valid UTF-8' => [" \t src/caf\xE9 \n", "src/caf\xE9"];
        yield 'a continuation byte at the edges of text that is not valid UTF-8' => ["\xA0caf\xE9\xA0", "\xA0caf\xE9\xA0"];
        yield 'text that is not valid UTF-8 as it was typed' => ["src/caf\xE9", "src/caf\xE9"];
    }
}
