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

use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\HistoricalCorrelationStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\BuiltInStageName;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\HistoricalStatus;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AuditHistoryStoreInterface;

final class HistoricalCorrelationStageTest extends TestCase
{
    private string $tmpDir;

    public function test_name_returns_built_in_value(): void
    {
        $stage = new HistoricalCorrelationStage($this->makeStore(), new NullLogger());

        self::assertSame(BuiltInStageName::HistoricalCorrelation->value, $stage->name());
    }

    public function test_it_skips_when_disabled(): void
    {
        $store = self::createMock(AuditHistoryStoreInterface::class);
        $store->expects(self::never())->method('loadFingerprints');
        $store->expects(self::never())->method('storeFingerprints');

        $stage = new HistoricalCorrelationStage($store, new NullLogger(), false);
        $stage->process(AuditContext::forProject($this->tmpDir));
    }

    public function test_it_tags_finding_as_new_when_not_in_previous_audit(): void
    {
        $vulnerability = $this->makeValidatedVulnerability();

        $store = $this->makeStore(previous: []);
        $auditContext = $this->makeContextWith($vulnerability);

        (new HistoricalCorrelationStage($store, new NullLogger(), true))->process($auditContext);

        $stored = $auditContext->vulnerabilities()[$vulnerability->id()];
        self::assertSame(HistoricalStatus::New, $stored->historicalStatus());
    }

    public function test_it_tags_finding_as_still_present_when_in_previous_audit(): void
    {
        $vulnerability = $this->makeValidatedVulnerability();

        $store = $this->makeStore(previous: [$vulnerability->fingerprint()]);
        $auditContext = $this->makeContextWith($vulnerability);

        (new HistoricalCorrelationStage($store, new NullLogger(), true))->process($auditContext);

        $stored = $auditContext->vulnerabilities()[$vulnerability->id()];
        self::assertSame(HistoricalStatus::StillPresent, $stored->historicalStatus());
    }

    public function test_it_records_new_and_still_present_counts_in_meta(): void
    {
        $present = $this->makeValidatedVulnerability(filePath: 'src/Repository/UserRepository.php');
        $fresh = $this->makeValidatedVulnerability(filePath: 'src/Repository/OrderRepository.php');

        $store = $this->makeStore(previous: [$present->fingerprint()]);
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->addVulnerability($present);
        $auditContext->addVulnerability($fresh);

        (new HistoricalCorrelationStage($store, new NullLogger(), true))->process($auditContext);

        self::assertSame(1, $auditContext->getMeta('audit.history.still_present'));
        self::assertSame(1, $auditContext->getMeta('audit.history.new'));
    }

    public function test_it_reports_fixed_count_for_fingerprints_gone_since_last_run(): void
    {
        $present = $this->makeValidatedVulnerability();

        $store = $this->makeStore(previous: [$present->fingerprint(), 'FP-OLDGONEXXXXX']);
        $auditContext = $this->makeContextWith($present);

        (new HistoricalCorrelationStage($store, new NullLogger(), true))->process($auditContext);

        self::assertSame(1, $auditContext->getMeta('audit.history.fixed'));
        self::assertSame(['FP-OLDGONEXXXXX'], $auditContext->getMeta('audit.history.fixed_fingerprints'));
    }

    public function test_it_persists_current_fingerprints_for_next_run(): void
    {
        $vulnerability = $this->makeValidatedVulnerability();

        $store = $this->makeStore(previous: []);
        $auditContext = $this->makeContextWith($vulnerability);

        (new HistoricalCorrelationStage($store, new NullLogger(), true))->process($auditContext);

        self::assertSame([$vulnerability->fingerprint()], $store->stored);
    }

    public function test_it_only_correlates_validated_findings(): void
    {
        $validated = $this->makeValidatedVulnerability(filePath: 'src/Repository/UserRepository.php');
        $unvalidated = $this->makeVulnerability(filePath: 'src/Repository/OrderRepository.php');

        $store = $this->makeStore(previous: []);
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->addVulnerability($validated);
        $auditContext->addVulnerability($unvalidated);

        (new HistoricalCorrelationStage($store, new NullLogger(), true))->process($auditContext);

        self::assertSame([$validated->fingerprint()], $store->stored);
    }

    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir().'/historical_correlation_test_'.uniqid('', true);
        mkdir($this->tmpDir, 0o777, true);
    }

    protected function tearDown(): void
    {
        rmdir($this->tmpDir);
    }

    private function makeContextWith(Vulnerability $vulnerability): AuditContext
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->addVulnerability($vulnerability);

        return $auditContext;
    }

    /**
     * @param list<string> $previous
     */
    private function makeStore(array $previous = []): object
    {
        return new class($previous) implements AuditHistoryStoreInterface {
            /** @var list<string> */
            public array $stored = [];

            /** @param list<string> $previous */
            public function __construct(
                private readonly array $previous,
            ) {}

            public function loadFingerprints(string $projectIdentifier): array
            {
                return $this->previous;
            }

            public function storeFingerprints(string $projectIdentifier, array $fingerprints): void
            {
                $this->stored = $fingerprints;
            }
        };
    }

    private function makeValidatedVulnerability(string $filePath = 'src/Repository/UserRepository.php'): Vulnerability
    {
        return $this->makeVulnerability($filePath)->withReviewerValidation(true);
    }

    private function makeVulnerability(string $filePath = 'src/Repository/UserRepository.php'): Vulnerability
    {
        return Vulnerability::create(
            vulnerabilityType: VulnerabilityType::SQL_INJECTION,
            vulnerabilitySeverity: VulnerabilitySeverity::HIGH,
            title: 'SQLi',
            description: 'd',
            filePath: $filePath,
            lineStart: 10,
            lineEnd: 15,
            vulnerableCode: '$conn->query($input)',
            attackVector: 'a',
            proof: 'p',
            remediation: 'r',
            confidence: 0.9,
        );
    }
}
