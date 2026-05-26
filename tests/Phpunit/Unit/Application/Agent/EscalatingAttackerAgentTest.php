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
use Psr\Log\NullLogger;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAgentInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\EscalatingAttackerAgent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\CoverageRecorderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\NullCoverageRecorder;

final class EscalatingAttackerAgentTest extends TestCase
{
    public function test_it_skips_expensive_pass_when_cheap_finds_nothing(): void
    {
        $cheap = $this->makeRecordingAttacker([]);
        $expensive = $this->makeRecordingAttacker([]);

        $escalating = new EscalatingAttackerAgent($cheap, $expensive, new NullLogger());

        $result = $escalating->analyze(
            [$this->makeFile('src/Controller/A.php')],
            SymfonyMapping::create(),
            new NullCoverageRecorder(),
        );

        self::assertSame([], $result);
        self::assertSame(1, $cheap->callCount);
        self::assertSame(0, $expensive->callCount);
    }

    public function test_it_runs_expensive_pass_only_on_files_flagged_by_cheap(): void
    {
        $files = [
            $this->makeFile('src/Controller/A.php'),
            $this->makeFile('src/Controller/B.php'),
            $this->makeFile('src/Controller/C.php'),
        ];

        $cheap = $this->makeRecordingAttacker([
            $this->makeVulnerability('src/Controller/A.php'),
        ]);
        $expensive = $this->makeRecordingAttacker([]);

        $escalating = new EscalatingAttackerAgent($cheap, $expensive, new NullLogger());

        $escalating->analyze($files, SymfonyMapping::create(), new NullCoverageRecorder());

        self::assertSame(1, $expensive->callCount);
        self::assertCount(1, $expensive->lastFiles);
        self::assertSame('src/Controller/A.php', $expensive->lastFiles[0]->relativePath());
    }

    public function test_expensive_findings_supersede_cheap_findings_on_overlap(): void
    {
        $cheapVuln = $this->makeVulnerability(
            'src/Controller/A.php',
            VulnerabilitySeverity::MEDIUM,
            title: 'cheap version',
        );
        $expensiveVuln = $this->makeVulnerability(
            'src/Controller/A.php',
            VulnerabilitySeverity::HIGH,
            title: 'expensive version',
        );

        $cheap = $this->makeRecordingAttacker([$cheapVuln]);
        $expensive = $this->makeRecordingAttacker([$expensiveVuln]);

        $escalating = new EscalatingAttackerAgent($cheap, $expensive, new NullLogger());

        $result = $escalating->analyze(
            [$this->makeFile('src/Controller/A.php')],
            SymfonyMapping::create(),
            new NullCoverageRecorder(),
        );

        self::assertCount(1, $result);
        self::assertSame('expensive version', $result[0]->title());
    }

    public function test_cheap_findings_on_files_expensive_did_not_re_flag_are_kept(): void
    {
        $cheapOnA = $this->makeVulnerability('src/Controller/A.php', title: 'cheap A');
        $cheapOnB = $this->makeVulnerability('src/Controller/B.php', title: 'cheap B');
        $expensiveOnA = $this->makeVulnerability('src/Controller/A.php', title: 'expensive A');

        $cheap = $this->makeRecordingAttacker([$cheapOnA, $cheapOnB]);
        $expensive = $this->makeRecordingAttacker([$expensiveOnA]);

        $escalating = new EscalatingAttackerAgent($cheap, $expensive, new NullLogger());

        $result = $escalating->analyze(
            [$this->makeFile('src/Controller/A.php'), $this->makeFile('src/Controller/B.php')],
            SymfonyMapping::create(),
            new NullCoverageRecorder(),
        );

        $titles = array_map(static fn (Vulnerability $vulnerability): string => $vulnerability->title(), $result);
        self::assertContains('expensive A', $titles);
        self::assertContains('cheap B', $titles);
    }

    public function test_expensive_pass_receives_cheap_findings_as_previous_context(): void
    {
        $cheapVuln = $this->makeVulnerability('src/Controller/A.php');

        $cheap = $this->makeRecordingAttacker([$cheapVuln]);
        $expensive = $this->makeRecordingAttacker([]);

        $escalating = new EscalatingAttackerAgent($cheap, $expensive, new NullLogger());

        $escalating->analyze(
            [$this->makeFile('src/Controller/A.php')],
            SymfonyMapping::create(),
            new NullCoverageRecorder(),
        );

        self::assertSame([$cheapVuln], $expensive->lastPreviousFindings);
    }

    private function makeFile(string $path): ProjectFile
    {
        return ProjectFile::create($path, '/app/'.$path, '<?php');
    }

    private function makeVulnerability(
        string $filePath,
        VulnerabilitySeverity $severity = VulnerabilitySeverity::HIGH,
        string $title = 'v',
    ): Vulnerability {
        return Vulnerability::create(
            vulnerabilityType: VulnerabilityType::SQL_INJECTION,
            vulnerabilitySeverity: $severity,
            title: $title,
            description: 'd',
            filePath: $filePath,
            lineStart: 10,
            lineEnd: 15,
            vulnerableCode: 'c',
            attackVector: 'a',
            proof: 'p',
            remediation: 'r',
            confidence: 0.9,
        );
    }

    /**
     * @param list<Vulnerability> $returnedFindings
     */
    private function makeRecordingAttacker(array $returnedFindings): object
    {
        return new class($returnedFindings) implements AttackerAgentInterface {
            public int $callCount = 0;

            /** @var list<ProjectFile> */
            public array $lastFiles = [];

            /** @var list<Vulnerability> */
            public array $lastPreviousFindings = [];

            /** @param list<Vulnerability> $returnedFindings */
            public function __construct(
                private readonly array $returnedFindings,
            ) {}

            public function analyze(
                array $files,
                SymfonyMapping $symfonyMapping,
                CoverageRecorderInterface $coverageRecorder,
                bool $bypassCache = false,
                array $previousFindings = [],
            ): array {
                ++$this->callCount;
                $this->lastFiles = $files;
                $this->lastPreviousFindings = $previousFindings;

                return $this->returnedFindings;
            }
        };
    }
}
