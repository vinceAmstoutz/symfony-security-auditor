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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Command;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditCommandHelp;

final class AuditCommandHelpTest extends TestCase
{
    public function test_exit_code_two_documentation_covers_the_preflight_unpriced_model_abort_with_no_report_emitted(): void
    {
        self::assertStringContainsString('an unpriced model', AuditCommandHelp::HELP);
        self::assertStringContainsString('no report emitted in that case', AuditCommandHelp::HELP);
    }

    public function test_exit_code_two_documentation_still_covers_the_mid_run_budget_abort_with_a_partial_report(): void
    {
        self::assertStringContainsString('partial report still emitted', AuditCommandHelp::HELP);
    }
}
