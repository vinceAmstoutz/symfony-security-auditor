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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Standalone;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\AuditedProjectConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandaloneConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandalonePlatformConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\ProjectConfigNotices;

final class ProjectConfigNoticesTest extends TestCase
{
    private const string WORKING_DIRECTORY_NOTICE = 'Project config /work/.symfony-security-auditor.yaml is layered over your user config: the audited repository may tune the audit through it (paths, profile, models, a tighter budget), never the platform and its credentials, the cache, privacy, custom skills, secret scrubbing, custom risk patterns or imported SARIF.';

    private const string AUDITED_PROJECT_NOTICE = 'Audited project config /repo/.symfony-security-auditor.yaml is layered over the configuration read before it: the audited repository may tune the audit through it (paths, profile, models, a tighter budget), never the platform and its credentials, the cache, privacy, custom skills, secret scrubbing, custom risk patterns or imported SARIF.';

    public function test_it_says_nothing_when_no_project_config_was_layered_in(): void
    {
        self::assertSame([], ProjectConfigNotices::of($this->config(null, null)));
    }

    public function test_it_names_the_config_of_the_working_directory(): void
    {
        self::assertSame([self::WORKING_DIRECTORY_NOTICE], ProjectConfigNotices::of($this->config('/work/.symfony-security-auditor.yaml', null)));
    }

    public function test_it_names_the_config_of_the_audited_project(): void
    {
        self::assertSame(
            [self::AUDITED_PROJECT_NOTICE],
            ProjectConfigNotices::of($this->config(null, AuditedProjectConfig::layered('/repo/.symfony-security-auditor.yaml', [], null))),
        );
    }

    public function test_it_names_every_file_read_lowest_priority_first(): void
    {
        self::assertSame(
            [self::WORKING_DIRECTORY_NOTICE, self::AUDITED_PROJECT_NOTICE],
            ProjectConfigNotices::of($this->config('/work/.symfony-security-auditor.yaml', AuditedProjectConfig::layered('/repo/.symfony-security-auditor.yaml', [], null))),
        );
    }

    public function test_it_names_the_skipped_file_with_its_reason_after_the_one_it_was_meant_to_override(): void
    {
        self::assertSame(
            [
                self::WORKING_DIRECTORY_NOTICE,
                'Audited project config /repo/.symfony-security-auditor.yaml was skipped and the run goes on without it: The project config "/repo/.symfony-security-auditor.yaml" declares "cache", which decides what the run spends, trusts or writes.',
            ],
            ProjectConfigNotices::of($this->config(
                '/work/.symfony-security-auditor.yaml',
                AuditedProjectConfig::skipped('/repo/.symfony-security-auditor.yaml', 'The project config "/repo/.symfony-security-auditor.yaml" declares "cache", which decides what the run spends, trusts or writes.'),
            )),
        );
    }

    public function test_it_escapes_the_percent_signs_of_the_paths_and_of_the_reason_for_the_container(): void
    {
        self::assertSame(
            [
                str_replace('/work/', '/100%%/work/', self::WORKING_DIRECTORY_NOTICE),
                'Audited project config /repo/%%weird%%/.symfony-security-auditor.yaml was skipped and the run goes on without it: sets "%%env(X)%%"',
            ],
            ProjectConfigNotices::of($this->config(
                '/100%/work/.symfony-security-auditor.yaml',
                AuditedProjectConfig::skipped('/repo/%weird%/.symfony-security-auditor.yaml', 'sets "%env(X)%"'),
            )),
        );
    }

    private function config(?string $projectConfigFile, ?AuditedProjectConfig $auditedProjectConfig): StandaloneConfig
    {
        return new StandaloneConfig([], new StandalonePlatformConfig([]), $projectConfigFile, auditedProjectConfig: $auditedProjectConfig);
    }
}
