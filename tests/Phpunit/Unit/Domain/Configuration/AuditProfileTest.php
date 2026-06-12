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
    #[DataProvider('profileDefaults')]
    public function test_profile_resolves_its_documented_defaults(
        AuditProfile $auditProfile,
        int $maxIterations,
        bool $leanMode,
        bool $codeSlicing,
        bool $poCSynthesis,
        int $reviewerMaxConcurrent,
    ): void {
        self::assertSame($maxIterations, $auditProfile->maxIterations());
        self::assertSame($leanMode, $auditProfile->staticPreScanLeanMode());
        self::assertSame($codeSlicing, $auditProfile->codeSlicingEnabled());
        self::assertSame($poCSynthesis, $auditProfile->poCSynthesisEnabled());
        self::assertSame($reviewerMaxConcurrent, $auditProfile->reviewerMaxConcurrent());
    }

    /** @return iterable<string, array{AuditProfile, int, bool, bool, bool, int}> */
    public static function profileDefaults(): iterable
    {
        yield 'fast' => [AuditProfile::Fast, 1, true, true, false, 4];
        yield 'balanced' => [AuditProfile::Balanced, 3, false, false, false, 1];
        yield 'thorough' => [AuditProfile::Thorough, 3, false, false, true, 1];
    }
}
