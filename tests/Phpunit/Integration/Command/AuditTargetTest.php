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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Command;

use Override;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditTarget;

final class AuditTargetTest extends TestCase
{
    private string $project;

    #[Override]
    protected function setUp(): void
    {
        $this->project = sys_get_temp_dir().'/audit_target_'.uniqid('', true).'/site';
        (new Filesystem())->dumpFile($this->project.'/composer.json', '{}');
        (new Filesystem())->dumpFile($this->project.'/apps/api/src/ApiAction.php', '<?php final class ApiAction {}');
        (new Filesystem())->dumpFile($this->project.'/apps/api/lib/Legacy.php', '<?php final class Legacy {}');
    }

    #[Override]
    protected function tearDown(): void
    {
        (new Filesystem())->remove(\dirname($this->project));
    }

    public function test_without_a_scan_a_directory_holding_a_default_scan_path_is_the_project(): void
    {
        $auditTarget = AuditTarget::named($this->project.'/apps/api', []);

        self::assertSame($this->project.'/apps/api', $auditTarget->projectPath);
        self::assertSame([], $auditTarget->scanPaths);
        self::assertNull($auditTarget->folder);
    }

    public function test_without_a_scan_a_directory_holding_none_names_a_folder_of_the_project_it_lies_in(): void
    {
        $auditTarget = AuditTarget::named($this->project.'/apps/api/lib', []);

        self::assertSame($this->project, $auditTarget->projectPath);
        self::assertSame([$this->project.'/apps/api/lib'], $auditTarget->scanPaths);
        self::assertSame($this->project.'/apps/api/lib', $auditTarget->folder);
    }
}
