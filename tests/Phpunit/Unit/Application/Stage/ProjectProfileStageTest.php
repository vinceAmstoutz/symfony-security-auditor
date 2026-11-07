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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Stage;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\ProjectProfileStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AccessControlMap;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ArchitectureStyle;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileInventory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\InstalledPackagesReaderInterface;

final class ProjectProfileStageTest extends TestCase
{
    /**
     * @throws InvalidAuditContextException
     */
    public function test_the_packages_the_audited_project_locks_reach_the_mapping(): void
    {
        $auditContext = AuditContext::forProject(sys_get_temp_dir());
        $auditContext->setMapping(SymfonyMapping::of(ProjectFileInventory::fromFiles([]), new AccessControlMap()));

        $installedPackagesReader = self::createStub(InstalledPackagesReaderInterface::class);
        $installedPackagesReader->method('read')->willReturnCallback(static fn (string $projectPath): ?array => sys_get_temp_dir() === $projectPath ? ['symfony/ai-agent' => 'v0.15.0'] : null);

        (new ProjectProfileStage($installedPackagesReader))->process($auditContext);

        self::assertFalse($auditContext->mapping()?->projectProfile()->satisfies('api-platform/core'));
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    public function test_the_layout_of_the_mapped_files_reaches_the_mapping(): void
    {
        $auditContext = AuditContext::forProject(sys_get_temp_dir());
        $auditContext->setMappingFiles([ProjectFile::create('src/Ordering/Application/PlaceOrderCommandHandler.php', '/app/a', '<?php final class PlaceOrderCommandHandler {}')]);
        $auditContext->setMapping(SymfonyMapping::of(ProjectFileInventory::fromFiles([]), new AccessControlMap()));

        (new ProjectProfileStage(self::createStub(InstalledPackagesReaderInterface::class)))->process($auditContext);

        self::assertSame([ArchitectureStyle::CQRS], $auditContext->mapping()?->projectProfile()->architectureStyles());
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_a_run_that_mapped_nothing_gets_no_mapping_from_the_profile(): void
    {
        $auditContext = AuditContext::forProject(sys_get_temp_dir());

        (new ProjectProfileStage(self::createStub(InstalledPackagesReaderInterface::class)))->process($auditContext);

        self::assertNull($auditContext->mapping());
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    public function test_the_bounded_contexts_of_the_mapped_files_reach_the_mapping(): void
    {
        $auditContext = AuditContext::forProject(sys_get_temp_dir());
        $auditContext->setMappingFiles([
            ProjectFile::create('src/Billing/Domain/Invoice.php', '/app/a', '<?php final class Invoice {}'),
            ProjectFile::create('src/Identity/Domain/User.php', '/app/b', '<?php final class User {}'),
        ]);
        $auditContext->setMapping(SymfonyMapping::of(ProjectFileInventory::fromFiles([]), new AccessControlMap()));

        (new ProjectProfileStage(self::createStub(InstalledPackagesReaderInterface::class)))->process($auditContext);

        self::assertSame(['Billing', 'Identity'], $auditContext->mapping()?->projectProfile()->boundedContexts());
    }
}
