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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectLayoutDetector;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectProfile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\StageInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\InstalledPackagesReaderInterface;

/**
 * Profiles the audited project once its mapping is built: the packages its
 * lockfile installs and the architecture its files are laid out in, which
 * decide the hunting instructions the attacker is given.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ProjectProfileStage implements StageInterface
{
    public function __construct(
        private InstalledPackagesReaderInterface $installedPackagesReader,
    ) {}

    #[Override]
    public function name(): string
    {
        return 'project_profile';
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
        )));
    }
}
