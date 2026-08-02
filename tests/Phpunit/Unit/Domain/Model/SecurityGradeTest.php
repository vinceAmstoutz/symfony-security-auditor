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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Domain\Model;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SecurityGrade;

final class SecurityGradeTest extends TestCase
{
    #[DataProvider('boundaryCases')]
    public function test_it_derives_a_grade_from_a_normalized_score(int $normalizedScore, SecurityGrade $securityGrade): void
    {
        self::assertSame($securityGrade, SecurityGrade::fromNormalizedScore($normalizedScore));
    }

    /**
     * @return iterable<string, array{int, SecurityGrade}>
     */
    public static function boundaryCases(): iterable
    {
        yield 'a perfect score is an A' => [100, SecurityGrade::A];
        yield 'the lowest A' => [96, SecurityGrade::A];
        yield 'the highest B' => [95, SecurityGrade::B];
        yield 'the lowest B' => [86, SecurityGrade::B];
        yield 'the highest C' => [85, SecurityGrade::C];
        yield 'the lowest C' => [71, SecurityGrade::C];
        yield 'the highest D' => [70, SecurityGrade::D];
        yield 'the lowest D' => [51, SecurityGrade::D];
        yield 'the highest F' => [50, SecurityGrade::F];
        yield 'a floored score is an F' => [0, SecurityGrade::F];
    }
}
