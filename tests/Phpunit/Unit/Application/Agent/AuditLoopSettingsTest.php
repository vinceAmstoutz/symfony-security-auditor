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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AuditLoopSettings;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Configuration\ToolsScope;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;

final class AuditLoopSettingsTest extends TestCase
{
    public function test_the_tools_open_the_audited_files_unless_told_otherwise(): void
    {
        self::assertSame(ToolsScope::Audited, (new AuditLoopSettings())->toolsScope);
        self::assertSame(ToolsScope::Scanned, (new AuditLoopSettings(toolsScope: ToolsScope::Scanned))->toolsScope);
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    public function test_the_tools_open_the_files_being_audited_in_the_audited_scope_and_every_scanned_file_in_the_scanned_one(): void
    {
        $projectFile = ProjectFile::create('src/A.php', '/app/src/A.php', '<?php');
        $scanned = ProjectFile::create('src/B.php', '/app/src/B.php', '<?php');
        $auditContext = AuditContext::forProject(__DIR__);
        $auditContext->setProjectFiles([$projectFile]);
        $auditContext->setMappingFiles([$projectFile, $scanned]);

        self::assertNull((new AuditLoopSettings())->toolFiles($auditContext));
        self::assertSame([$projectFile, $scanned], (new AuditLoopSettings(toolsScope: ToolsScope::Scanned))->toolFiles($auditContext));
    }
}
