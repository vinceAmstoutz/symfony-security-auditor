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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Domain\Configuration;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Configuration\AuditProfile;

final class AuditProfileTest extends TestCase
{
    /**
     * @param array{
     *     maxIterations: int,
     *     leanMode: bool,
     *     codeSlicing: bool,
     *     poCSynthesis: bool,
     *     reviewerMaxConcurrent: int,
     *     attackerMaxConcurrent: int,
     *     sinceClosure: string,
     * } $expected
     */
    #[DataProvider('profileDefaults')]
    public function test_profile_resolves_its_documented_defaults(
        AuditProfile $auditProfile,
        array $expected,
    ): void {
        self::assertSame($expected['maxIterations'], $auditProfile->maxIterations());
        self::assertSame($expected['leanMode'], $auditProfile->staticPreScanLeanMode());
        self::assertSame($expected['codeSlicing'], $auditProfile->codeSlicingEnabled());
        self::assertSame($expected['poCSynthesis'], $auditProfile->poCSynthesisEnabled());
        self::assertSame($expected['reviewerMaxConcurrent'], $auditProfile->reviewerMaxConcurrent());
        self::assertSame($expected['attackerMaxConcurrent'], $auditProfile->attackerMaxConcurrent());
        self::assertSame($expected['sinceClosure'], $auditProfile->sinceClosure());
    }

    /**
     * @return iterable<string, array{AuditProfile, array{
     *     maxIterations: int,
     *     leanMode: bool,
     *     codeSlicing: bool,
     *     poCSynthesis: bool,
     *     reviewerMaxConcurrent: int,
     *     attackerMaxConcurrent: int,
     *     sinceClosure: string,
     * }}>
     */
    public static function profileDefaults(): iterable
    {
        yield 'fast' => [AuditProfile::Fast, [
            'maxIterations' => 1,
            'leanMode' => true,
            'codeSlicing' => true,
            'poCSynthesis' => false,
            'reviewerMaxConcurrent' => 4,
            'attackerMaxConcurrent' => 4,
            'sinceClosure' => 'none',
        ]];
        yield 'balanced' => [AuditProfile::Balanced, [
            'maxIterations' => 3,
            'leanMode' => false,
            'codeSlicing' => false,
            'poCSynthesis' => false,
            'reviewerMaxConcurrent' => 1,
            'attackerMaxConcurrent' => 1,
            'sinceClosure' => 'none',
        ]];
        yield 'thorough' => [AuditProfile::Thorough, [
            'maxIterations' => 3,
            'leanMode' => false,
            'codeSlicing' => false,
            'poCSynthesis' => true,
            'reviewerMaxConcurrent' => 1,
            'attackerMaxConcurrent' => 1,
            'sinceClosure' => 'direct',
        ]];
    }
}
