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

use PHPUnit\Framework\Attributes\DataProvider;
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
        $installedPackagesReader->method('read')->willReturnCallback(static fn (string $projectPath): ?array => sys_get_temp_dir() === $projectPath ? ['symfony/http-kernel' => 'v8.1.0', 'symfony/ai-agent' => 'v0.15.0'] : null);

        (new ProjectProfileStage($installedPackagesReader))->process($auditContext);

        self::assertFalse($auditContext->mapping()?->projectProfile()->satisfies('api-platform/core'));
    }

    /**
     * @param list<string> $scanPaths
     *
     * @throws InvalidAuditContextException
     */
    #[DataProvider('narrowedRuns')]
    public function test_a_run_reads_the_lock_of_the_one_application_its_paths_lie_in_or_else_the_project_s(array $scanPaths, string $lockedMarker): void
    {
        $auditContext = AuditContext::forProject(sys_get_temp_dir(), $scanPaths);
        $auditContext->setMapping(SymfonyMapping::of(ProjectFileInventory::fromFiles([]), new AccessControlMap()));

        $locks = [
            '' => 'marker/project',
            '/apps' => 'marker/apps',
            '/apps/api' => 'marker/api',
            '/../other' => 'marker/outside',
        ];
        $installedPackagesReader = self::createStub(InstalledPackagesReaderInterface::class);
        $installedPackagesReader->method('read')->willReturnCallback(static fn (string $path): ?array => match (true) {
            \sprintf('%s/apps/api/tools', sys_get_temp_dir()) === $path => ['marker/tools' => '1.0.0'],
            \array_key_exists(substr($path, \strlen(sys_get_temp_dir())), $locks) => ['symfony/http-kernel' => 'v8.1.0', $locks[substr($path, \strlen(sys_get_temp_dir()))] => '1.0.0'],
            default => null,
        });

        (new ProjectProfileStage($installedPackagesReader))->process($auditContext);

        self::assertSame([$lockedMarker], array_values(array_filter([...$locks, 'marker/tools'], static fn (string $marker): bool => $auditContext->mapping()?->projectProfile()->satisfies($marker) ?? false)));
    }

    /**
     * @return iterable<string, array{list<string>, string}>
     */
    public static function narrowedRuns(): iterable
    {
        yield 'a folder of an application' => [['apps/api/src'], 'marker/api'];
        yield 'a folder under a lock that installs no kernel' => [['apps/api/tools/bin'], 'marker/api'];
        yield 'an application holding another' => [['apps/web'], 'marker/apps'];
        yield 'two folders of one application' => [['apps/api/src', 'apps/api/config'], 'marker/api'];
        yield 'folders of two applications' => [['apps/api', 'apps/web'], 'marker/project'];
        yield 'a folder in no application' => [['src'], 'marker/project'];
        yield 'an application and a folder in none' => [['apps/api', 'src'], 'marker/project'];
        yield 'no path' => [[], 'marker/project'];
        yield 'a path above the project' => [['../other'], 'marker/project'];
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
