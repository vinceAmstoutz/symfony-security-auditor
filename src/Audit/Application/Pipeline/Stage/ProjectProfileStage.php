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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage;

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\BuiltInStageName;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectLayoutDetector;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectProfile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\StageInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\InstalledPackagesReaderInterface;

/**
 * Profiles the audited project after mapping: the packages its lockfile
 * installs and its file layout, which decide the attacker's hunting
 * instructions.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class ProjectProfileStage implements StageInterface
{
    public function __construct(
        private InstalledPackagesReaderInterface $installedPackagesReader,
    ) {}

    #[Override]
    public function name(): string
    {
        return BuiltInStageName::ProjectProfile->value;
    }

    #[Override]
    public function process(AuditContext $auditContext): void
    {
        $symfonyMapping = $auditContext->mapping();
        if (!$symfonyMapping instanceof SymfonyMapping) {
            return;
        }

        $auditContext->setMapping($symfonyMapping->withProjectProfile(ProjectProfile::of(
            $this->installedPackagesReader->read($auditContext->projectPath()),
            ProjectLayoutDetector::stylesOf($auditContext->mappingFiles()),
            ProjectLayoutDetector::boundedContextsOf($auditContext->mappingFiles()),
        )));
    }
}
