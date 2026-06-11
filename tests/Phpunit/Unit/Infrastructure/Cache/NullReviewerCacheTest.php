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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Cache;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\NullReviewerCache;

final class NullReviewerCacheTest extends TestCase
{
    public function test_get_always_misses(): void
    {
        self::assertNull((new NullReviewerCache())->get($this->makeVulnerability(), 'code'));
    }

    public function test_get_misses_even_after_store(): void
    {
        $nullReviewerCache = new NullReviewerCache();
        $vulnerability = $this->makeVulnerability();

        $nullReviewerCache->store($vulnerability, 'code', ['accepted' => true]);

        self::assertNull($nullReviewerCache->get($vulnerability, 'code'));
    }

    private function makeVulnerability(): Vulnerability
    {
        return Vulnerability::create(
            vulnerabilityType: VulnerabilityType::SQL_INJECTION,
            vulnerabilitySeverity: VulnerabilitySeverity::HIGH,
            title: 'T',
            description: 'd',
            filePath: 'src/A.php',
            lineStart: 1,
            lineEnd: 2,
            vulnerableCode: 'c',
            attackVector: 'a',
            proof: 'p',
            remediation: 'r',
            confidence: 0.9,
        );
    }
}
