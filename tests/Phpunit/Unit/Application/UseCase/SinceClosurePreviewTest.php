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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\UseCase;

use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\DependencyExpansionStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\SinceClosurePreview;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\StageInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\UseCase\Fixture\SinceClosureFixture;

final class SinceClosurePreviewTest extends TestCase
{
    /**
     * @throws InvalidProjectFileException
     * @throws InvalidAuditContextException
     */
    public function test_it_adds_the_controllers_a_changed_voter_guards(): void
    {
        $files = SinceClosureFixture::files();

        $auditedFiles = SinceClosureFixture::preview('direct')->auditedFiles(sys_get_temp_dir(), [], 'main', [$files[2]], $files);

        self::assertSame(
            ['src/Security/PostVoter.php', 'src/Controller/PostController.php'],
            array_map(static fn (ProjectFile $projectFile): string => $projectFile->relativePath(), $auditedFiles),
        );
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidAuditContextException
     */
    public function test_it_adds_only_the_guarded_controllers_under_the_paths_of_the_run(): void
    {
        $files = SinceClosureFixture::files();

        $auditedFiles = SinceClosureFixture::preview('direct')->auditedFiles(sys_get_temp_dir(), ['src/Security'], 'main', [$files[2]], $files);

        self::assertSame([$files[2]], $auditedFiles);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidAuditContextException
     */
    public function test_it_maps_nothing_and_keeps_the_diff_when_the_closure_does_not_widen_the_run(): void
    {
        $files = SinceClosureFixture::files();
        $mappingStage = $this->createMock(StageInterface::class);
        $mappingStage->expects(self::never())->method('process');

        $auditedFiles = (new SinceClosurePreview($mappingStage, new DependencyExpansionStage(new NullLogger(), 'none')))
            ->auditedFiles(sys_get_temp_dir(), [], 'main', [$files[2], $files[0]], $files);

        self::assertSame([$files[2], $files[0]], $auditedFiles);
    }
}
