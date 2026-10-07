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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture;

use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Symfony\Component\Validator\Validation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAgent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAnalysisSettings;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerLlmCollaborators;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerScanCollaborators;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AuditLoopSettings;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AuditOrchestrator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerAgent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerAgentCollaborators;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerModeConfiguration;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\VulnerabilityFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AccessControlMap;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileInventory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullCodeSlicer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullProgressReporter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullStaticPreScanner;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\NullAttackerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\AttackerPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\ReviewerPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Pipeline\Fixture\RecordingProgressReporter;

final class AuditOrchestratorHarness
{
    /**
     * @param array{
     *     logger?: LoggerInterface,
     *     maxIterations?: int,
     *     minConfidence?: float,
     *     recordingProgressReporter?: RecordingProgressReporter,
     * } $overrides
     */
    public static function orchestrator(
        LLMClientInterface $attackerLlm,
        LLMClientInterface $reviewerLlm,
        array $overrides = [],
    ): AuditOrchestrator {
        return new AuditOrchestrator(
            attackerAgent: new AttackerAgent(
                new AttackerLlmCollaborators(
                    $attackerLlm,
                    new AttackerPromptBuilder(),
                    new VulnerabilityFactory(new NullLogger(), Validation::createValidator()),
                    new NullCodeSlicer(),
                ),
                new AttackerScanCollaborators(
                    new NullAttackerCache(),
                    new NullStaticPreScanner(),
                    new NullProgressReporter(),
                ),
                new AttackerAnalysisSettings(),
                new NullLogger(),
            ),
            reviewerAgent: new ReviewerAgent(
                new ReviewerAgentCollaborators(
                    $reviewerLlm,
                    new ReviewerPromptBuilder(),
                    new NullLogger(),
                    progressReporter: $overrides['recordingProgressReporter'] ?? new NullProgressReporter(),
                ),
                new ReviewerModeConfiguration(),
            ),
            logger: $overrides['logger'] ?? new NullLogger(),
            auditLoopSettings: new AuditLoopSettings(
                $overrides['maxIterations'] ?? AuditOrchestrator::DEFAULT_MAX_ITERATIONS,
                $overrides['minConfidence'] ?? AuditOrchestrator::DEFAULT_MIN_CONFIDENCE,
            ),
            progressReporter: $overrides['recordingProgressReporter'] ?? new NullProgressReporter(),
        );
    }

    /**
     * @param list<string> $acceptedFingerprints
     *
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    public static function contextWithMapping(string $projectPath, array $acceptedFingerprints = []): AuditContext
    {
        $auditContext = AuditContext::forProject($projectPath, acceptedFingerprints: $acceptedFingerprints);
        $auditContext->setProjectFiles([
            ProjectFile::create('src/Controller/Foo.php', '/app/src/Controller/Foo.php', '<?php'),
        ]);
        $auditContext->setMapping(SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()));

        return $auditContext;
    }

    /**
     * @return array<string, mixed>
     */
    public static function vulnerabilityPayload(
        string $title = 'Vuln',
        float $confidence = 0.9,
        int $lineStart = 10,
        int $lineEnd = 15,
        string $filePath = 'src/Controller/FooController.php',
    ): array {
        return [
            'type' => 'sql_injection',
            'severity' => 'high',
            'title' => $title,
            'description' => 'desc',
            'file_path' => $filePath,
            'line_start' => $lineStart,
            'line_end' => $lineEnd,
            'vulnerable_code' => '$db->query($input)',
            'attack_vector' => 'SQL injection',
            'proof' => "' OR 1=1",
            'remediation' => 'Use prepared statements',
            'confidence' => $confidence,
        ];
    }

    /**
     * @param list<array<string, mixed>> $vulnerabilities
     *
     * @throws InvalidTokenUsageException
     */
    public static function attackerResponse(array $vulnerabilities): LLMResponse
    {
        return LLMResponse::of((string) json_encode($vulnerabilities), 'test', 'end_turn', TokenUsageSnapshot::of(0, 0));
    }

    /**
     * @throws InvalidTokenUsageException
     */
    public static function reviewerAcceptResponse(): LLMResponse
    {
        return LLMResponse::of((string) json_encode(['accepted' => true]), 'test', 'end_turn', TokenUsageSnapshot::of(0, 0));
    }
}
