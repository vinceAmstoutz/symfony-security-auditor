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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Tool;

use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolDefinition;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\InMemoryAdvisoryDatabase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Tool\SymfonyToolRegistryFactory;

final class SymfonyToolRegistryFactoryTest extends TestCase
{
    public function test_registry_exposes_all_four_built_in_tools(): void
    {
        $symfonyToolRegistryFactory = new SymfonyToolRegistryFactory(new NullLogger(), new InMemoryAdvisoryDatabase());

        $toolRegistry = $symfonyToolRegistryFactory->forProjectFiles([
            ProjectFile::create('src/A.php', '/app/x', '<?php'),
        ]);

        $names = array_map(static fn (ToolDefinition $toolDefinition): string => $toolDefinition->name, $toolRegistry->definitions());
        sort($names);

        self::assertSame(['grep', 'list_files', 'lookup_advisory', 'read_file'], $names);
    }

    public function test_read_file_tool_can_access_provided_project_files(): void
    {
        $symfonyToolRegistryFactory = new SymfonyToolRegistryFactory(new NullLogger(), new InMemoryAdvisoryDatabase());

        $toolRegistry = $symfonyToolRegistryFactory->forProjectFiles([
            ProjectFile::create('src/A.php', '/app/x', '<?php echo "marker-7";'),
        ]);

        self::assertSame('<?php echo "marker-7";', $toolRegistry->execute('read_file', ['relative_path' => 'src/A.php']));
    }

    public function test_each_call_returns_an_independent_registry(): void
    {
        $symfonyToolRegistryFactory = new SymfonyToolRegistryFactory(new NullLogger(), new InMemoryAdvisoryDatabase());

        $toolRegistry = $symfonyToolRegistryFactory->forProjectFiles([ProjectFile::create('src/A.php', '/x', 'aaa')]);
        $secondRegistry = $symfonyToolRegistryFactory->forProjectFiles([ProjectFile::create('src/B.php', '/x', 'bbb')]);

        self::assertSame('aaa', $toolRegistry->execute('read_file', ['relative_path' => 'src/A.php']));
        self::assertSame('bbb', $secondRegistry->execute('read_file', ['relative_path' => 'src/B.php']));
        self::assertStringContainsString('Error', $secondRegistry->execute('read_file', ['relative_path' => 'src/A.php']));
    }
}
