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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\PoCSynthesizerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\PoCSynthesisStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\BuiltInStageName;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\CodeLocation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityClassification;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityNarrative;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;

final class PoCSynthesisStageTest extends TestCase
{
    private string $tmpDir;

    public function test_name_returns_built_in_stage_value(): void
    {
        $poCSynthesisStage = new PoCSynthesisStage(
            $this->makeNoopSynthesizer(),
            new NullLogger(),
        );

        self::assertSame(BuiltInStageName::PoCSynthesis->value, $poCSynthesisStage->name());
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_it_skips_when_disabled(): void
    {
        $synthesizer = self::createMock(PoCSynthesizerInterface::class);
        $synthesizer->expects(self::never())->method('synthesize');

        $poCSynthesisStage = new PoCSynthesisStage($synthesizer, new NullLogger(), false);
        $poCSynthesisStage->process(AuditContext::forProject($this->tmpDir));
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     */
    public function test_it_does_not_call_synthesizer_when_no_validated_findings(): void
    {
        $synthesizer = self::createMock(PoCSynthesizerInterface::class);
        $synthesizer->expects(self::never())->method('synthesize');

        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->addVulnerability($this->makeVulnerability());

        $poCSynthesisStage = new PoCSynthesisStage($synthesizer, new NullLogger(), true);
        $poCSynthesisStage->process($auditContext);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     */
    public function test_it_replaces_validated_findings_with_enriched_copies(): void
    {
        $vulnerability = $this->makeVulnerability()->withReviewerValidation(true);
        $enriched = $vulnerability->withSynthesizedPoC('curl /x');

        $synthesizer = self::createStub(PoCSynthesizerInterface::class);
        $synthesizer->method('synthesize')->willReturn([$enriched]);

        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->addVulnerability($vulnerability);

        $poCSynthesisStage = new PoCSynthesisStage($synthesizer, new NullLogger(), true);
        $poCSynthesisStage->process($auditContext);

        $stored = $auditContext->vulnerabilities()[$vulnerability->id()];
        self::assertSame('curl /x', $stored->synthesizedPoC());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     */
    public function test_it_records_count_metadata_in_context(): void
    {
        $vulnerability = $this->makeVulnerability()->withReviewerValidation(true);
        $enriched = $vulnerability->withSynthesizedPoC('curl /x');

        $synthesizer = self::createStub(PoCSynthesizerInterface::class);
        $synthesizer->method('synthesize')->willReturn([$enriched]);

        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->addVulnerability($vulnerability);

        $poCSynthesisStage = new PoCSynthesisStage($synthesizer, new NullLogger(), true);
        $poCSynthesisStage->process($auditContext);

        self::assertSame(1, $auditContext->getMeta('audit.poc_synthesized'));
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     */
    public function test_it_does_not_replace_findings_whose_poc_remained_null(): void
    {
        $vulnerability = $this->makeVulnerability()->withReviewerValidation(true);

        $synthesizer = self::createStub(PoCSynthesizerInterface::class);
        $synthesizer->method('synthesize')->willReturn([$vulnerability]);

        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->addVulnerability($vulnerability);

        $poCSynthesisStage = new PoCSynthesisStage($synthesizer, new NullLogger(), true);
        $poCSynthesisStage->process($auditContext);

        $stored = $auditContext->vulnerabilities()[$vulnerability->id()];
        self::assertNull($stored->synthesizedPoC());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     */
    public function test_disabled_stage_does_not_synthesize_even_with_validated_findings(): void
    {
        $synthesizer = self::createMock(PoCSynthesizerInterface::class);
        $synthesizer->expects(self::never())->method('synthesize');

        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->addVulnerability($this->makeVulnerability()->withReviewerValidation(true));

        (new PoCSynthesisStage($synthesizer, new NullLogger(), false))->process($auditContext);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     */
    public function test_stage_is_disabled_by_default_even_with_validated_findings(): void
    {
        $synthesizer = self::createMock(PoCSynthesizerInterface::class);
        $synthesizer->expects(self::never())->method('synthesize');

        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->addVulnerability($this->makeVulnerability()->withReviewerValidation(true));

        (new PoCSynthesisStage($synthesizer, new NullLogger()))->process($auditContext);
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_it_logs_debug_when_disabled(): void
    {
        $bufferingLogger = new BufferingLogger();

        (new PoCSynthesisStage($this->makeNoopSynthesizer(), $bufferingLogger, false))
            ->process(AuditContext::forProject($this->tmpDir));

        self::assertSame([], $this->contextOf($bufferingLogger->cleanLogs(), 'PoC synthesis stage disabled, skipping'));
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     */
    public function test_it_logs_when_there_are_no_validated_findings(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->addVulnerability($this->makeVulnerability());

        $bufferingLogger = new BufferingLogger();
        (new PoCSynthesisStage($this->makeNoopSynthesizer(), $bufferingLogger, true))->process($auditContext);

        self::assertSame([], $this->contextOf($bufferingLogger->cleanLogs(), 'PoC synthesis: no validated findings to enrich'));
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     */
    public function test_it_logs_completion_with_enriched_and_total_counts(): void
    {
        $vulnerability = $this->makeVulnerability()->withReviewerValidation(true);

        $synthesizer = self::createStub(PoCSynthesizerInterface::class);
        $synthesizer->method('synthesize')->willReturn([$vulnerability->withSynthesizedPoC('curl /x')]);

        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->addVulnerability($vulnerability);

        $bufferingLogger = new BufferingLogger();
        (new PoCSynthesisStage($synthesizer, $bufferingLogger, true))->process($auditContext);

        self::assertSame(
            ['enriched' => 1, 'total_validated' => 1],
            $this->contextOf($bufferingLogger->cleanLogs(), 'PoC synthesis stage complete'),
        );
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    public function test_it_persists_already_synthesized_pocs_before_a_budget_abort_discards_the_rest(): void
    {
        $first = $this->makeVulnerabilityAt('src/A.php');
        $second = $this->makeVulnerabilityAt('src/B.php');

        $synthesizer = self::createStub(PoCSynthesizerInterface::class);
        $synthesizer->method('synthesize')->willReturnCallback(
            static function (array $vulnerabilities) use ($first): array {
                $vulnerability = $vulnerabilities[0];
                self::assertInstanceOf(Vulnerability::class, $vulnerability);

                if ($vulnerability->filePath() === $first->filePath()) {
                    return [$vulnerability->withSynthesizedPoC('curl /x')];
                }

                throw BudgetExceededException::forTokens(500, 100);
            },
        );

        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->addVulnerability($first);
        $auditContext->addVulnerability($second);

        $budgetExceeded = false;
        try {
            (new PoCSynthesisStage($synthesizer, new NullLogger(), true))->process($auditContext);
        } catch (BudgetExceededException) {
            $budgetExceeded = true;
        }

        self::assertTrue($budgetExceeded, 'The stage must rethrow BudgetExceededException.');
        $stored = $auditContext->vulnerabilities()[$first->id()];
        self::assertSame('curl /x', $stored->synthesizedPoC());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    public function test_it_persists_already_synthesized_pocs_before_a_provider_exception_discards_the_rest(): void
    {
        $first = $this->makeVulnerabilityAt('src/A.php');
        $second = $this->makeVulnerabilityAt('src/B.php');

        $synthesizer = self::createStub(PoCSynthesizerInterface::class);
        $synthesizer->method('synthesize')->willReturnCallback(
            static function (array $vulnerabilities) use ($first): array {
                $vulnerability = $vulnerabilities[0];
                self::assertInstanceOf(Vulnerability::class, $vulnerability);

                if ($vulnerability->filePath() === $first->filePath()) {
                    return [$vulnerability->withSynthesizedPoC('curl /x')];
                }

                throw new LLMProviderException('platform unreachable');
            },
        );

        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->addVulnerability($first);
        $auditContext->addVulnerability($second);

        $providerFailed = false;
        try {
            (new PoCSynthesisStage($synthesizer, new NullLogger(), true))->process($auditContext);
        } catch (LLMProviderException) {
            $providerFailed = true;
        }

        self::assertTrue($providerFailed, 'The stage must rethrow LLMProviderException.');
        $stored = $auditContext->vulnerabilities()[$first->id()];
        self::assertSame('curl /x', $stored->synthesizedPoC());
    }

    #[Override]
    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir().'/poc_synthesis_stage_test_'.uniqid('', true);
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

    private function makeNoopSynthesizer(): PoCSynthesizerInterface
    {
        return new class implements PoCSynthesizerInterface {
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
