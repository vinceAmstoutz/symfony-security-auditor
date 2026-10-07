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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM;

use PHPUnit\Framework\TestCase;
use Symfony\AI\Platform\PlainConverter;
use Symfony\AI\Platform\Result\DeferredResult;
use Symfony\AI\Platform\Result\InMemoryRawResult;
use Symfony\AI\Platform\Result\TextResult;
use Symfony\AI\Platform\TokenUsage\TokenUsage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\BudgetTracker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\CostCalculator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditBudgetException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditBudget;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\PricingProviderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformResultExtractor;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\ToolIterationBooker;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\FakeRateLimiter;

final class ToolIterationBookerTest extends TestCase
{
    /**
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     */
    public function test_it_books_the_round_on_the_rate_limit_window_when_no_budget_is_tracked(): void
    {
        $fakeRateLimiter = new FakeRateLimiter();
        $toolIterationBooker = new ToolIterationBooker('m', $fakeRateLimiter, null, new PlatformResultExtractor(null));

        $toolIterationBooker->book($this->deferredResult(), TokenUsageSnapshot::of(10, 5, 3, 2));

        self::assertSame([[10, 5]], $fakeRateLimiter->recorded);
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidAuditBudgetException
     * @throws InvalidTokenUsageException
     */
    public function test_it_books_the_round_against_the_budget_under_the_model_the_provider_reports(): void
    {
        $budgetTracker = $this->budgetTracker(AuditBudget::unlimited());
        $toolIterationBooker = new ToolIterationBooker('configured', new FakeRateLimiter(), $budgetTracker, new PlatformResultExtractor(null));

        $toolIterationBooker->book($this->deferredResult('reported'), TokenUsageSnapshot::of(10, 5, 3, 2));

        self::assertSame(20, $budgetTracker->tokensUsed());
        self::assertSame(['reported'], $budgetTracker->usageByModel()['configured']['billed_models']);
    }

    /**
     * @throws InvalidAuditBudgetException
     * @throws InvalidTokenUsageException
     */
    public function test_it_records_the_round_on_the_rate_limit_window_before_the_budget_aborts_the_run(): void
    {
        $fakeRateLimiter = new FakeRateLimiter();
        $toolIterationBooker = new ToolIterationBooker('m', $fakeRateLimiter, $this->budgetTracker(AuditBudget::forTokens(19)), new PlatformResultExtractor(null));

        try {
            $toolIterationBooker->book($this->deferredResult(), TokenUsageSnapshot::of(10, 5, 3, 2));
            self::fail('The budget the round spent must abort the run.');
        } catch (BudgetExceededException) {
            self::assertSame([[10, 5]], $fakeRateLimiter->recorded);
        }
    }

    private function budgetTracker(AuditBudget $auditBudget): BudgetTracker
    {
        $pricingProvider = self::createStub(PricingProviderInterface::class);
        $pricingProvider->method('hasModel')->willReturn(true);

        return new BudgetTracker($auditBudget, new CostCalculator($pricingProvider));
    }

    private function deferredResult(?string $reportedModel = null): DeferredResult
    {
        $deferredResult = new DeferredResult(new PlainConverter(new TextResult('ok')), new InMemoryRawResult([], [], (object) []));
        $deferredResult->getMetadata()->add('token_usage', new TokenUsage(promptTokens: 10, completionTokens: 5, model: $reportedModel));

        return $deferredResult;
    }
}
