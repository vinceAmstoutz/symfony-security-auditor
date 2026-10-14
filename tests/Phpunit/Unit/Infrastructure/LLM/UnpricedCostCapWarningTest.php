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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\LLM;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditBudgetException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditBudget;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\WarningCollectingLogger;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\LLM\Fixture\OneModelPricingProvider;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\LLM\Fixture\UnpricedCostCapWarnings;

final class UnpricedCostCapWarningTest extends TestCase
{
    /**
     * @throws InvalidAuditBudgetException
     * @throws InvalidTokenUsageException
     */
    public function test_a_cost_cap_is_said_to_hold_no_answer_under_a_model_without_a_price_once_per_model(): void
    {
        $warningCollectingLogger = new WarningCollectingLogger();
        $unpricedCostCapWarning = UnpricedCostCapWarnings::of(AuditBudget::forBoth(1000, 5.0), $warningCollectingLogger);

        foreach (['acme-secure-v2', OneModelPricingProvider::PRICED_MODEL, 'acme-secure-v2', 'acme-fast'] as $model) {
            $unpricedCostCapWarning->check($this->answerFrom($model));
        }

        self::assertSame(
            [[UnpricedCostCapWarnings::messageFor('acme-secure-v2'), []], [UnpricedCostCapWarnings::messageFor('acme-fast'), []]],
            $warningCollectingLogger->warnings,
        );
    }

    /**
     * @throws InvalidAuditBudgetException
     * @throws InvalidTokenUsageException
     */
    public function test_no_warning_is_given_without_a_cost_cap(): void
    {
        $warningCollectingLogger = new WarningCollectingLogger();

        UnpricedCostCapWarnings::of(AuditBudget::forTokens(1000), $warningCollectingLogger)->check($this->answerFrom('acme-secure-v2'));

        self::assertSame([], $warningCollectingLogger->warnings);
    }

    /**
     * @throws InvalidAuditBudgetException
     * @throws InvalidTokenUsageException
     */
    public function test_the_model_an_answer_is_billed_as_is_the_one_named(): void
    {
        $warningCollectingLogger = new WarningCollectingLogger();

        UnpricedCostCapWarnings::of(AuditBudget::forCost(5.0), $warningCollectingLogger)->check($this->answerFrom('acme-secure-v2')->withReportedModel(OneModelPricingProvider::PRICED_MODEL));

        self::assertSame([], $warningCollectingLogger->warnings);
    }

    /**
     * @throws InvalidTokenUsageException
     */
    private function answerFrom(string $model): LLMResponse
    {
        return LLMResponse::of('[]', $model, 'end_turn', TokenUsageSnapshot::of(1, 1));
    }
}
