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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Stage;

use Override;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\ErrorHandler\BufferingLogger;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\FixSynthesizerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\FixSynthesisStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityNarrativeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\BuiltInStageName;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\CodeLocation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityClassification;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityNarrative;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;

final class FixSynthesisStageTest extends TestCase
{
    private string $tmpDir;

    public function test_name_returns_the_built_in_stage_value(): void
    {
        self::assertSame(
            BuiltInStageName::FixSynthesis->value,
            (new FixSynthesisStage($this->makeNoopSynthesizer(), new NullLogger()))->name(),
        );
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_it_is_disabled_by_default(): void
    {
        $synthesizer = self::createMock(FixSynthesizerInterface::class);
        $synthesizer->expects(self::never())->method('synthesize');

        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->addVulnerability($this->makeVulnerability()->withReviewerValidation(true));

        (new FixSynthesisStage($synthesizer, new NullLogger()))->process($auditContext);
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_it_skips_and_logs_when_disabled(): void
    {
        $synthesizer = self::createMock(FixSynthesizerInterface::class);
        $synthesizer->expects(self::never())->method('synthesize');

        $bufferingLogger = new BufferingLogger();
        (new FixSynthesisStage($synthesizer, $bufferingLogger, false))->process(AuditContext::forProject($this->tmpDir));

        self::assertSame([], $this->contextOf($bufferingLogger->cleanLogs(), 'Fix synthesis stage disabled, skipping'));
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_it_does_not_call_the_synthesizer_when_no_validated_findings(): void
    {
        $synthesizer = self::createMock(FixSynthesizerInterface::class);
        $synthesizer->expects(self::never())->method('synthesize');

        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->addVulnerability($this->makeVulnerability());

        $bufferingLogger = new BufferingLogger();
        (new FixSynthesisStage($synthesizer, $bufferingLogger, true))->process($auditContext);

        self::assertSame([], $this->contextOf($bufferingLogger->cleanLogs(), 'Fix synthesis: no validated findings to enrich'));
        self::assertNull($auditContext->getMeta('audit.fix_synthesized'));
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_it_replaces_a_validated_finding_with_its_patched_copy_and_records_the_count(): void
    {
        $vulnerability = $this->makeVulnerability()->withReviewerValidation(true);

        $synthesizer = self::createStub(FixSynthesizerInterface::class);
        $synthesizer->method('synthesize')->willReturn([$vulnerability->withSuggestedFix('--- a/x')]);

        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->addVulnerability($vulnerability);

        $bufferingLogger = new BufferingLogger();
        (new FixSynthesisStage($synthesizer, $bufferingLogger, true))->process($auditContext);

        self::assertSame('--- a/x', $auditContext->vulnerabilities()[$vulnerability->id()]->suggestedFix());
        self::assertSame(1, $auditContext->getMeta('audit.fix_synthesized'));
        self::assertSame(
            ['enriched' => 1, 'total_validated' => 1],
            $this->contextOf($bufferingLogger->cleanLogs(), 'Fix synthesis stage complete'),
        );
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_it_does_not_replace_a_finding_whose_fix_remained_null(): void
    {
        $vulnerability = $this->makeVulnerability()->withReviewerValidation(true);

        $synthesizer = self::createStub(FixSynthesizerInterface::class);
        $synthesizer->method('synthesize')->willReturn([$vulnerability]);

        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->addVulnerability($vulnerability);

        (new FixSynthesisStage($synthesizer, new NullLogger(), true))->process($auditContext);

        self::assertNull($auditContext->vulnerabilities()[$vulnerability->id()]->suggestedFix());
        self::assertSame(0, $auditContext->getMeta('audit.fix_synthesized'));
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_it_persists_already_patched_findings_before_a_budget_abort_discards_the_rest(): void
    {
        $first = $this->makeVulnerabilityAt('src/A.php');
        $second = $this->makeVulnerabilityAt('src/B.php');

        $synthesizer = self::createStub(FixSynthesizerInterface::class);
        $synthesizer->method('synthesize')->willReturnCallback(
            static function (array $vulnerabilities) use ($first): array {
                $vulnerability = $vulnerabilities[0];
                self::assertInstanceOf(Vulnerability::class, $vulnerability);

                if ($vulnerability->filePath() === $first->filePath()) {
                    return [$vulnerability->withSuggestedFix('--- a/A')];
                }

                throw BudgetExceededException::forTokens(500, 100);
            },
        );

        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->addVulnerability($first);
        $auditContext->addVulnerability($second);

        $budgetExceeded = false;
        try {
            (new FixSynthesisStage($synthesizer, new NullLogger(), true))->process($auditContext);
        } catch (BudgetExceededException) {
            $budgetExceeded = true;
        }

        self::assertTrue($budgetExceeded, 'The stage must rethrow BudgetExceededException.');
        self::assertSame('--- a/A', $auditContext->vulnerabilities()[$first->id()]->suggestedFix());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_it_persists_already_patched_findings_before_a_provider_exception_discards_the_rest(): void
    {
        $first = $this->makeVulnerabilityAt('src/A.php');
        $second = $this->makeVulnerabilityAt('src/B.php');

        $synthesizer = self::createStub(FixSynthesizerInterface::class);
        $synthesizer->method('synthesize')->willReturnCallback(
            static function (array $vulnerabilities) use ($first): array {
                $vulnerability = $vulnerabilities[0];
                self::assertInstanceOf(Vulnerability::class, $vulnerability);

                if ($vulnerability->filePath() === $first->filePath()) {
                    return [$vulnerability->withSuggestedFix('--- a/A')];
                }

                throw new LLMProviderException('platform unreachable');
            },
        );

        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->addVulnerability($first);
        $auditContext->addVulnerability($second);

        $providerFailed = false;
        try {
            (new FixSynthesisStage($synthesizer, new NullLogger(), true))->process($auditContext);
        } catch (LLMProviderException) {
            $providerFailed = true;
        }

        self::assertTrue($providerFailed, 'The stage must rethrow LLMProviderException.');
        self::assertSame('--- a/A', $auditContext->vulnerabilities()[$first->id()]->suggestedFix());
    }

    #[Override]
    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir().'/fix_synthesis_stage_test_'.uniqid('', true);
        mkdir($this->tmpDir, 0o777, true);
    }

    #[Override]
    protected function tearDown(): void
    {
        rmdir($this->tmpDir);
    }

    /**
     * @param array<mixed> $logs
     *
     * @return array<mixed>
     */
    private function contextOf(array $logs, string $message): array
    {
        foreach ($logs as $log) {
            self::assertIsArray($log);
            if ($message === ($log[1] ?? null)) {
                $context = $log[2] ?? [];
                self::assertIsArray($context);

                return $context;
            }
        }

        self::fail(\sprintf('No log entry with message "%s"', $message));
    }

    private function makeNoopSynthesizer(): FixSynthesizerInterface
    {
        return new class implements FixSynthesizerInterface {
            #[Override]
            public function synthesize(array $vulnerabilities): array
            {
                return $vulnerabilities;
            }
        };
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    private function makeVulnerability(): Vulnerability
    {
        return Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, 'Test', 0.9),
            new CodeLocation('src/Controller/Foo.php', 10, 15),
            new VulnerabilityNarrative('d', 'av', 'proof', 'r'),
            'code',
        );
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    private function makeVulnerabilityAt(string $filePath): Vulnerability
    {
        return Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, 'Test', 0.9),
            new CodeLocation($filePath, 10, 15),
            new VulnerabilityNarrative('d', 'av', 'proof', 'r'),
            'code',
        )->withReviewerValidation(true);
    }
}
