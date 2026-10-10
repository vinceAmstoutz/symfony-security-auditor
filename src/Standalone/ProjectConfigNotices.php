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

namespace VinceAmstoutz\SymfonySecurityAuditor\Standalone;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\AuditedProjectConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\ContainerParameterSyntax;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandaloneConfig;

/**
 * The audited repository may tune the run through the config files it ships,
 * so the audit header says which ones were layered in, lowest priority first,
 * and which one was left out and why: a stricter `fail_on` or another model
 * coming from the checkout rather than from the user's own file would
 * otherwise be silent.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ProjectConfigNotices
{
    private const string WORKING_DIRECTORY_CONFIG = 'Project config %s is layered over your user config: the audited repository may tune the audit through it (paths, profile, models, a tighter budget), never the platform and its credentials, the cache, privacy, custom skills, secret scrubbing, custom risk patterns or imported SARIF.';

    private const string AUDITED_PROJECT_CONFIG = 'Audited project config %s is layered over the configuration read before it: the audited repository may tune the audit through it (paths, profile, models, a tighter budget), never the platform and its credentials, the cache, privacy, custom skills, secret scrubbing, custom risk patterns or imported SARIF.';

    private const string SKIPPED_AUDITED_PROJECT_CONFIG = 'Audited project config %s was skipped and the run goes on without it: %s';

    /**
     * @return list<string> escaped for the container, as parameter values
     */
    public static function of(StandaloneConfig $standaloneConfig): array
    {
        $notices = [];

        if (null !== $standaloneConfig->projectConfigFile) {
            $notices[] = ContainerParameterSyntax::escape(\sprintf(self::WORKING_DIRECTORY_CONFIG, $standaloneConfig->projectConfigFile));
        }

        if ($standaloneConfig->auditedProjectConfig instanceof AuditedProjectConfig) {
            $notices[] = ContainerParameterSyntax::escape(self::auditedProjectNotice($standaloneConfig->auditedProjectConfig));
        }

        return $notices;
    }

    private static function auditedProjectNotice(AuditedProjectConfig $auditedProjectConfig): string
    {
        return null === $auditedProjectConfig->skipReason
            ? \sprintf(self::AUDITED_PROJECT_CONFIG, $auditedProjectConfig->file)
            : \sprintf(self::SKIPPED_AUDITED_PROJECT_CONFIG, $auditedProjectConfig->file, $auditedProjectConfig->skipReason);
    }
}
