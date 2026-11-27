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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Prompt\Skill;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\ConfigAttackerSkill;

final class ConfigAttackerSkillTest extends TestCase
{
    public function test_it_leaves_out_a_credential_only_a_test_or_dev_environment_reads(): void
    {
        self::assertStringContainsString('A credential only a test or dev environment reads', (new ConfigAttackerSkill())->block());
    }
}
