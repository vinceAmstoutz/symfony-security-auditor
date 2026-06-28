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

use Override;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;

final class AuditContextDiffTest extends TestCase
{
    private string $tmpDir;

    public function test_diff_since_ref_is_null_by_default(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);

        self::assertNull($auditContext->diffSinceRef());
    }

    public function test_diff_since_ref_is_persisted_when_provided(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir, [], false, 'origin/main');

        self::assertSame('origin/main', $auditContext->diffSinceRef());
    }

    #[Override]
    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir().'/audit_context_diff_test_'.uniqid('', true);
        mkdir($this->tmpDir, 0o777, true);
    }

    #[Override]
    protected function tearDown(): void
    {
        rmdir($this->tmpDir);
    }
}
