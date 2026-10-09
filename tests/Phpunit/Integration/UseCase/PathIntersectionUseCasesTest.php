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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\UseCase;

use Override;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunking\FileChunker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\CostCalculator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\EstimateAuditCostUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\ListScannedFilesUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditCostException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\ProjectFileScanner;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\TokenEstimator\ResolvingTokenEstimator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Pricing\ModelsDevPricingProvider;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\AttackerSkillRegistry;

final class PathIntersectionUseCasesTest extends TestCase
{
    private string $projectDir;

    /**
     * @param list<string> $includedPaths
     * @param list<string> $scanPaths
     * @param list<string> $expected
     */
    #[DataProvider('pathScopes')]
    public function test_show_scanned_lists_the_configured_files_under_the_path_and_the_path_itself_only_when_the_configuration_reaches_none_of_it(array $includedPaths, array $scanPaths, array $expected): void
    {
        $files = (new ListScannedFilesUseCase(new ProjectFileScanner(new NullLogger(), $includedPaths)))->execute($this->projectDir, $scanPaths);

        self::assertSame($expected, array_map(static fn (ProjectFile $projectFile): string => $projectFile->relativePath(), $files));
    }

    /**
     * @param list<string> $includedPaths
     * @param list<string> $scanPaths
     * @param list<string> $expected
     *
     * @throws InvalidAuditContextException
     * @throws InvalidAuditCostException
     */
    #[DataProvider('pathScopes')]
    public function test_the_dry_run_estimates_the_files_a_run_audits(array $includedPaths, array $scanPaths, array $expected): void
    {
        $modelsDevPricingProvider = new ModelsDevPricingProvider(new NullLogger(), __DIR__.'/Fixture/pricing-catalog.json');
        $estimateAuditCostUseCase = new EstimateAuditCostUseCase(
            new ProjectFileScanner(new NullLogger(), $includedPaths),
            new ResolvingTokenEstimator(),
            new CostCalculator($modelsDevPricingProvider),
            new NullLogger(),
            new FileChunker(),
            new AttackerSkillRegistry(),
            'stub',
            1,
        );

        $auditReport = $estimateAuditCostUseCase->execute($this->projectDir, $scanPaths);

        self::assertSame(\count($expected), $auditReport->filesScanned());
        self::assertSame(\count($expected), $auditReport->filesDiscovered());
    }

    /**
     * @return iterable<string, array{list<string>, list<string>, list<string>}>
     */
    public static function pathScopes(): iterable
    {
        yield 'a path wider than the configured scope' => [['src/Controller'], ['src'], ['src/Controller/A.php']];
        yield 'a path inside the configured scope' => [['src', 'config'], ['src/Service'], ['src/Service/B.php']];
        yield 'a path the configured scope does not reach' => [['src'], ['apps/api'], ['apps/api/src/ApiController.php']];
        yield 'one path the configured scope reaches and one it does not' => [['src'], ['apps/api', 'src/Service'], ['src/Service/B.php']];
        yield 'no path' => [['src/Controller', 'config'], [], ['config/packages/security.yaml', 'src/Controller/A.php']];
    }

    #[Override]
    protected function setUp(): void
    {
        $this->projectDir = sys_get_temp_dir().'/path_intersection_use_cases_'.uniqid('', true);
        $filesystem = new Filesystem();
        $filesystem->dumpFile($this->projectDir.'/config/packages/security.yaml', 'security: {}');
        $filesystem->dumpFile($this->projectDir.'/src/Controller/A.php', '<?php class A {}');
        $filesystem->dumpFile($this->projectDir.'/src/Service/B.php', '<?php class B {}');
        $filesystem->dumpFile($this->projectDir.'/apps/api/src/ApiController.php', '<?php class ApiController {}');
    }

    #[Override]
    protected function tearDown(): void
    {
        (new Filesystem())->remove($this->projectDir);
    }
}
