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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Infrastructure\Pricing;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\BudgetTracker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\CostCalculator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditBudget;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Pricing\ModelsDevPricingProvider;

final class ReportedModelBillingTest extends TestCase
{
    /**
     * @throws InvalidTokenUsageException
     */
    #[DataProvider('reportedModelCases')]
    public function test_a_call_is_billed_at_the_serving_platform_rate(?string $platform, string $configuredModel, string $reportedModel, float $expectedCostUsd): void
    {
        $budgetTracker = new BudgetTracker(
            AuditBudget::unlimited(),
            new CostCalculator(new ModelsDevPricingProvider(new NullLogger(), __DIR__.'/Fixture/relisted-reported-model.json', 'vinceamstoutz/not-a-real-package', $platform)),
        );

        $budgetTracker->recordCall(LLMResponse::of('', $configuredModel, 'end_turn', TokenUsageSnapshot::of(1_000_000, 0))->withReportedModel($reportedModel));

        self::assertSame($expectedCostUsd, $budgetTracker->costUsdUsed());
    }

    /** @return iterable<string, array{?string, string, string, float}> */
    public static function reportedModelCases(): iterable
    {
        yield 'a reported model the serving platform lists' => ['venice', 'venice-uncensored', 'claude-opus-4-8', 6.0];
        yield 'a reported model only another provider lists' => ['venice', 'claude-opus-4-8', 'claude-opus-4-8-20260101', 6.0];
        yield 'a reported model on a platform with no listing of its own' => ['generic', 'gateway-route', 'claude-opus-4-8-20260101', 5.0];
        yield 'a reported model on a platform the catalog has no listing for' => ['together', 'gateway-route', 'claude-opus-4-8', 5.0];
        yield 'a reported model with no serving platform known' => [null, 'gateway-route', 'claude-opus-4-8', 5.0];
    }
}
