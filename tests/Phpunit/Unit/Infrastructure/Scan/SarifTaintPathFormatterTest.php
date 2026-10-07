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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Scan;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\SarifTaintPathFormatter;

final class SarifTaintPathFormatterTest extends TestCase
{
    /**
     * @param list<string|null> $rawSteps
     */
    #[DataProvider('taintPathCases')]
    public function test_it_appends_the_surviving_taint_path_to_the_message(array $rawSteps, string $expected): void
    {
        self::assertSame($expected, (new SarifTaintPathFormatter())->describe('Tainted SQL', $rawSteps));
    }

    /**
     * @return iterable<string, array{list<string|null>, string}>
     */
    public static function taintPathCases(): iterable
    {
        yield 'no steps leave the message untouched' => [[], 'Tainted SQL'];
        yield 'only dropped steps leave the message untouched' => [[null, null], 'Tainted SQL'];
        yield 'surviving steps are joined in order' => [['src/A.php:1', 'src/B.php:2'], 'Tainted SQL (taint path: src/A.php:1 -> src/B.php:2)'];
        yield 'a dropped leading step is marked by an ellipsis' => [[null, 'src/B.php:2'], 'Tainted SQL (taint path: ... -> src/B.php:2)'];
        yield 'a dropped middle step is marked by an ellipsis' => [['src/A.php:1', null, 'src/C.php:3'], 'Tainted SQL (taint path: src/A.php:1 -> ... -> src/C.php:3)'];
        yield 'consecutive dropped steps collapse to one ellipsis' => [['src/A.php:1', null, null, 'src/D.php:4'], 'Tainted SQL (taint path: src/A.php:1 -> ... -> src/D.php:4)'];
        yield 'a dropped trailing step is marked by an ellipsis' => [['src/A.php:1', null], 'Tainted SQL (taint path: src/A.php:1 -> ...)'];
    }
}
