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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Critic;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Critic\NullCoverageCritic;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AccessControlMap;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileInventory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;

final class NullCoverageCriticTest extends TestCase
{
    /**
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    public function test_a_disabled_critic_names_no_gap(): void
    {
        $auditContext = AuditContext::forProject(sys_get_temp_dir());
        $auditContext->setProjectFiles([ProjectFile::create('src/Controller/A.php', '/app/src/Controller/A.php', '<?php')]);

        self::assertSame([], (new NullCoverageCritic())->gaps(SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()), $auditContext));
    }
}
