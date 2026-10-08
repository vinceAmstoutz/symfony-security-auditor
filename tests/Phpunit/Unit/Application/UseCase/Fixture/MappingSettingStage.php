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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\UseCase\Fixture;

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\StageInterface;

/**
 * Sets a fixed mapping on the context it processes, or none, and records the files it was given to map.
 *
 * @internal scoped to the EstimateAuditCostUseCase tests
 */
final class MappingSettingStage implements StageInterface
{
    /** @var list<list<string>> */
    public array $mappedFiles = [];

    public function __construct(private readonly ?SymfonyMapping $symfonyMapping) {}

    #[Override]
    public function process(AuditContext $auditContext): void
    {
        $this->mappedFiles[] = array_map(static fn (ProjectFile $projectFile): string => $projectFile->relativePath(), $auditContext->mappingFiles());

        if ($this->symfonyMapping instanceof SymfonyMapping) {
            $auditContext->setMapping($this->symfonyMapping);
        }
    }

    #[Override]
    public function name(): string
    {
        return 'mapping';
    }
}
