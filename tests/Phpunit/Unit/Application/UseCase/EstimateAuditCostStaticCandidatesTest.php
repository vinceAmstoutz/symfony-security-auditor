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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\UseCase;

use Override;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunking\FileChunker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\CostCalculator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\EstimateAuditCostUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditCostException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityNarrativeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\CodeLocation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityClassification;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityNarrative;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AttackerSkillPromptRendererInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\CandidateFindingSourceInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\PricingProviderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProjectFileScannerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\TokenEstimatorInterface;

final class EstimateAuditCostStaticCandidatesTest extends TestCase
{
    /**
     * @throws InvalidAuditContextException
     * @throws InvalidAuditCostException
     * @throws InvalidCodeLocationException
     * @throws InvalidProjectFileException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_the_reviewer_estimate_sends_each_file_once_per_review_call_of_its_static_candidates(): void
    {
        $files = [
            ProjectFile::create('a.php', '/app/a.php', 'aaaa'),
            ProjectFile::create('b.php', '/app/b.php', 'bb'),
            ProjectFile::create('c.php', '/app/c.php', 'ccc'),
            ProjectFile::create('d.php', '/app/d.php', 'ddddddd'),
        ];
        $candidates = [
            ...$this->candidatesIn('a.php', 2),
            ...$this->candidatesIn('b.php', 21),
            ...$this->candidatesIn('c.php', 1),
        ];

        $auditReport = $this->useCase($files, $candidates)->execute(sys_get_temp_dir());

        self::assertSame(4 + 2 * 2 + 3, $auditReport->cost()->byRole()['reviewer']['input_tokens']);
    }

    /**
     * @param list<ProjectFile>   $files
     * @param list<Vulnerability> $candidates
     */
    private function useCase(array $files, array $candidates): EstimateAuditCostUseCase
    {
        $attackerSkillPromptRenderer = self::createStub(AttackerSkillPromptRendererInterface::class);
        $attackerSkillPromptRenderer->method('render')->willReturn('');

        return new EstimateAuditCostUseCase(
            new readonly class($files) implements ProjectFileScannerInterface {
                /** @param list<ProjectFile> $files */
                public function __construct(private array $files) {}

                #[Override]
                public function scan(string $projectPath): array
                {
                    return $this->files;
                }
            },
            new class implements TokenEstimatorInterface {
                #[Override]
                public function estimateTokens(string $text, string $model): int
                {
                    return mb_strlen($text);
                }
            },
            new CostCalculator(new class implements PricingProviderInterface {
                #[Override]
                public function pricePerMillionInputTokens(string $model): float
                {
                    return 0.0;
                }

                #[Override]
                public function pricePerMillionOutputTokens(string $model): float
                {
                    return 0.0;
                }

                #[Override]
                public function hasModel(string $model): bool
                {
                    return true;
                }
            }),
            new NullLogger(),
            new FileChunker(),
            $attackerSkillPromptRenderer,
            maxIterations: 1,
            reviewerInputRatio: 0.0,
            toolsEnabled: false,
            candidateFindingSource: new readonly class($files, $candidates) implements CandidateFindingSourceInterface {
                /**
                 * @param list<ProjectFile>   $files
                 * @param list<Vulnerability> $candidates
                 */
                public function __construct(private array $files, private array $candidates) {}

                #[Override]
                public function candidatesIn(array $files): array
                {
                    return $files === $this->files ? $this->candidates : [];
                }
            },
        );
    }

    /**
     * @return list<Vulnerability>
     *
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    private function candidatesIn(string $filePath, int $count): array
    {
        return array_map(
            static fn (int $line): Vulnerability => Vulnerability::of(
                new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, 'Static analysis: native query concat', 0.8),
                new CodeLocation($filePath, $line, $line),
                new VulnerabilityNarrative('d', 'a', 'p', 'r'),
                'c',
            ),
            range(1, $count),
        );
    }
}
