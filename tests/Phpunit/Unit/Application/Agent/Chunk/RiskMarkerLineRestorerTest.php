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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Chunk;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunk\RiskMarkerLineRestorer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidRiskMarkerException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RiskMarker;

final class RiskMarkerLineRestorerTest extends TestCase
{
    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     */
    public function test_it_restores_the_flagged_line_alone_when_its_statement_is_complete(): void
    {
        $projectFile = ProjectFile::create('src/A.php', '/app/src/A.php', "<?php\n\$a = 1;\n\$pdo->query(\$sql);\n\$b = 2;");

        $restored = (new RiskMarkerLineRestorer())->restore($projectFile, "<?php\n// elided\n// elided\n// elided", [$this->marker(3)]);

        self::assertSame("<?php\n// elided\n\$pdo->query(\$sql);\n// elided", $restored);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     */
    public function test_it_restores_every_line_of_the_call_a_flagged_line_leaves_open(): void
    {
        $projectFile = ProjectFile::create('src/A.php', '/app/src/A.php', "<?php\n\$rows = \$c->fetchAllAssociative(\n    \"SELECT * FROM t WHERE n = '\" . \$name . \"'\"\n);\n\$b = 2;");

        $restored = (new RiskMarkerLineRestorer())->restore($projectFile, "<?php\n// elided\n// elided\n// elided\n// elided", [$this->marker(2)]);

        self::assertSame("<?php\n\$rows = \$c->fetchAllAssociative(\n    \"SELECT * FROM t WHERE n = '\" . \$name . \"'\"\n);\n// elided", $restored);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     */
    public function test_it_restores_the_statement_of_each_flagged_line(): void
    {
        $projectFile = ProjectFile::create('src/A.php', '/app/src/A.php', "<?php\n\$one = \$pdo->query(\n    \$first\n);\n\$mid = 1;\n\$two = \$pdo->query(\n    \$second\n);");

        $restored = (new RiskMarkerLineRestorer())->restore($projectFile, implode("\n", ['<?php', ...array_fill(0, 7, '// elided')]), [$this->marker(2), $this->marker(6)]);

        self::assertSame("<?php\n\$one = \$pdo->query(\n    \$first\n);\n// elided\n\$two = \$pdo->query(\n    \$second\n);", $restored);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     */
    public function test_it_leaves_the_slicer_output_alone_for_a_flagged_line_the_file_does_not_have(): void
    {
        $projectFile = ProjectFile::create('src/A.php', '/app/src/A.php', "<?php\n\$a = 1;");

        $restored = (new RiskMarkerLineRestorer())->restore($projectFile, "<?php\n// elided", [$this->marker(9)]);

        self::assertSame("<?php\n// elided", $restored);
    }

    /**
     * @throws InvalidRiskMarkerException
     */
    private function marker(int $line): RiskMarker
    {
        return RiskMarker::create('src/A.php', $line, 'sql_injection', 'raw query concatenation');
    }
}
