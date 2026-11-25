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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Scan\ScanPathFilter;
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
 * instructions. A run whose `--path` values all lie in one monorepo
 * application reads the lockfile of that application, the nearest folder
 * above them whose `composer.lock` installs a kernel.
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
            $this->installedPackagesOf($auditContext),
            ProjectLayoutDetector::stylesOf($auditContext->mappingFiles()),
            ProjectLayoutDetector::boundedContextsOf($auditContext->mappingFiles()),
        )));
    }

    /**
     * @return array<string, string>|null
     */
    private function installedPackagesOf(AuditContext $auditContext): ?array
    {
        $applicationLocks = [];
        foreach (ScanPathFilter::normalize($auditContext->scanPaths()) as $scanPath) {
            [$folder, $installedPackages] = $this->nearestApplicationLock($auditContext->projectPath(), $scanPath);
            $applicationLocks[$folder] = $installedPackages;
        }

        return 1 === \count($applicationLocks) && !\array_key_exists('', $applicationLocks)
            ? reset($applicationLocks)
            : $this->installedPackagesReader->read($auditContext->projectPath());
    }

    /**
     * @return array{string, array<string, string>|null} the application folder (`''` when the path lies in none) and what its lockfile installs
     */
    private function nearestApplicationLock(string $projectPath, string $scanPath): array
    {
        $segments = explode('/', $scanPath);
        if (\in_array('..', $segments, true)) {
            return ['', null];
        }

        foreach (array_reverse(array_keys($segments)) as $last) {
            $folder = implode('/', \array_slice($segments, 0, $last + 1));
            $installedPackages = $this->installedPackagesReader->read(\sprintf('%s/%s', $projectPath, $folder));
            if (ProjectProfile::installsAKernel($installedPackages)) {
                return [$folder, $installedPackages];
            }
        }

        return ['', null];
    }
}
