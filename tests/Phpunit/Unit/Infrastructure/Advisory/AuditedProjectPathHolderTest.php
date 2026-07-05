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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Advisory;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\AuditedProjectPathHolder;

final class AuditedProjectPathHolderTest extends TestCase
{
    public function test_it_serves_the_default_path_until_a_run_sets_one(): void
    {
        $auditedProjectPathHolder = new AuditedProjectPathHolder('/app');

        self::assertSame('/app', $auditedProjectPathHolder->path());
    }

    public function test_the_audited_project_path_replaces_the_default(): void
    {
        $auditedProjectPathHolder = new AuditedProjectPathHolder('/app');

        $auditedProjectPathHolder->set('/audited/project');

        self::assertSame('/audited/project', $auditedProjectPathHolder->path());
    }
}
