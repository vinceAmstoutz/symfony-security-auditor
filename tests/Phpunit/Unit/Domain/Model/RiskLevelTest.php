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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RiskLevel;

final class RiskLevelTest extends TestCase
{
    #[DataProvider('thresholdCases')]
    public function test_is_at_least_compares_levels_by_ascending_severity(RiskLevel $level, RiskLevel $threshold, bool $expected): void
    {
        self::assertSame($expected, $level->isAtLeast($threshold));
    }

    /**
     * @return iterable<string, array{RiskLevel, RiskLevel, bool}>
     */
    public static function thresholdCases(): iterable
    {
        yield 'critical meets critical' => [RiskLevel::Critical, RiskLevel::Critical, true];
        yield 'high meets high' => [RiskLevel::High, RiskLevel::High, true];
        yield 'medium meets medium' => [RiskLevel::Medium, RiskLevel::Medium, true];
        yield 'low meets low' => [RiskLevel::Low, RiskLevel::Low, true];
        yield 'safe meets safe' => [RiskLevel::Safe, RiskLevel::Safe, true];

        yield 'critical meets high' => [RiskLevel::Critical, RiskLevel::High, true];
        yield 'high meets medium' => [RiskLevel::High, RiskLevel::Medium, true];
        yield 'medium meets low' => [RiskLevel::Medium, RiskLevel::Low, true];
        yield 'low meets safe' => [RiskLevel::Low, RiskLevel::Safe, true];
        yield 'critical meets safe' => [RiskLevel::Critical, RiskLevel::Safe, true];

        yield 'high does not meet critical' => [RiskLevel::High, RiskLevel::Critical, false];
        yield 'medium does not meet high' => [RiskLevel::Medium, RiskLevel::High, false];
        yield 'low does not meet medium' => [RiskLevel::Low, RiskLevel::Medium, false];
        yield 'safe does not meet low' => [RiskLevel::Safe, RiskLevel::Low, false];
        yield 'safe does not meet critical' => [RiskLevel::Safe, RiskLevel::Critical, false];
    }

    public function test_it_is_backed_by_lowercase_severity_names(): void
    {
        self::assertSame('critical', RiskLevel::Critical->value);
        self::assertSame('safe', RiskLevel::Safe->value);
    }

    #[DataProvider('rankCases')]
    public function test_rank_returns_an_ascending_ordinal(RiskLevel $riskLevel, int $expectedRank): void
    {
        self::assertSame($expectedRank, $riskLevel->rank());
    }

    /**
     * @return iterable<string, array{RiskLevel, int}>
     */
    public static function rankCases(): iterable
    {
        yield 'safe is 0' => [RiskLevel::Safe, 0];
        yield 'low is 1' => [RiskLevel::Low, 1];
        yield 'medium is 2' => [RiskLevel::Medium, 2];
        yield 'high is 3' => [RiskLevel::High, 3];
        yield 'critical is 4' => [RiskLevel::Critical, 4];
    }
}
