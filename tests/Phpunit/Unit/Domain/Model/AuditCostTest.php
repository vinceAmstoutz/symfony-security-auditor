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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Domain\Model;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditCostException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditCost;

final class AuditCostTest extends TestCase
{
    /**
     * @throws InvalidAuditCostException
     */
    public function test_of_constructs_and_exposes_all_fields(): void
    {
        $auditCost = AuditCost::of(100, 50, 0.0125, 'gpt-4o');

        self::assertSame(100, $auditCost->inputTokens());
        self::assertSame(50, $auditCost->outputTokens());
        self::assertSame(150, $auditCost->totalTokens());
        self::assertSame(0.0125, $auditCost->estimatedCostUsd());
        self::assertSame('gpt-4o', $auditCost->primaryModel());
    }

    public function test_zero_factory_constructs_empty_cost_for_model(): void
    {
        $auditCost = AuditCost::zero('claude-haiku-4-5-20251001');

        self::assertSame(0, $auditCost->totalTokens());
        self::assertSame(0.0, $auditCost->estimatedCostUsd());
        self::assertSame('claude-haiku-4-5-20251001', $auditCost->primaryModel());
    }

    /**
     * @throws InvalidAuditCostException
     */
    public function test_has_published_pricing_is_true_when_cost_is_nonzero(): void
    {
        $auditCost = AuditCost::of(100, 50, 0.05, 'claude-opus-4-7');

        self::assertTrue($auditCost->hasPublishedPricing());
    }

    /**
     * @throws InvalidAuditCostException
     */
    public function test_has_published_pricing_is_false_when_tokens_were_spent_but_cost_is_zero(): void
    {
        $auditCost = AuditCost::of(100, 50, 0.0, 'ollama/llama3.2');

        self::assertFalse($auditCost->hasPublishedPricing());
    }

    public function test_has_published_pricing_is_true_when_no_tokens_were_tracked_yet(): void
    {
        $auditCost = AuditCost::zero('');

        self::assertTrue($auditCost->hasPublishedPricing());
    }

    /**
     * @throws InvalidAuditCostException
     */
    public function test_has_published_pricing_is_false_when_one_split_role_prices_at_zero(): void
    {
        $auditCost = AuditCost::of(150, 75, 0.05, 'claude-opus-4-7', [
            'attacker' => ['model' => 'claude-opus-4-7', 'input_tokens' => 100, 'output_tokens' => 50, 'estimated_cost_usd' => 0.05],
            'reviewer' => ['model' => 'ollama/llama3.2', 'input_tokens' => 50, 'output_tokens' => 25, 'estimated_cost_usd' => 0.0],
        ]);

        self::assertFalse($auditCost->hasPublishedPricing());
    }

    /**
     * A priced cloud attacker paired with an unpriced local reviewer sums to a
     * nonzero total, so only a breakdown can catch it. A real run has no roles
     * to attribute, but it does record the model of every call.
     *
     * @throws InvalidAuditCostException
     */
    public function test_has_published_pricing_spots_an_unpriced_model_in_a_real_run(): void
    {
        $auditCost = AuditCost::of(120_000, 8_000, 1.87, 'claude-opus-5')->withUsageByModel([
            'claude-opus-5' => ['model' => 'claude-opus-5', 'input_tokens' => 100_000, 'output_tokens' => 7_000, 'estimated_cost_usd' => 1.87],
            'ollama/llama3.2' => ['model' => 'ollama/llama3.2', 'input_tokens' => 20_000, 'output_tokens' => 1_000, 'estimated_cost_usd' => 0.0],
        ]);

        self::assertFalse($auditCost->hasPublishedPricing());
    }

    /**
     * @throws InvalidAuditCostException
     */
    public function test_has_published_pricing_is_true_when_every_model_in_a_real_run_prices_above_zero(): void
    {
        $auditCost = AuditCost::of(120_000, 8_000, 1.88, 'claude-opus-5')->withUsageByModel([
            'claude-opus-5' => ['model' => 'claude-opus-5', 'input_tokens' => 100_000, 'output_tokens' => 7_000, 'estimated_cost_usd' => 1.87],
            'claude-haiku-4-5-20251001' => ['model' => 'claude-haiku-4-5-20251001', 'input_tokens' => 20_000, 'output_tokens' => 1_000, 'estimated_cost_usd' => 0.01],
        ]);

        self::assertTrue($auditCost->hasPublishedPricing());
    }

    /**
     * The per-role breakdown carries no cache-token keys, so `billableTokens()`
     * falls back for both. That fallback must be exactly zero: an entry that
     * spent nothing and priced to nothing is not a pricing gap, and any other
     * default would invent spend and report one.
     *
     * @throws InvalidAuditCostException
     */
    public function test_has_published_pricing_treats_a_role_entry_without_tokens_as_no_gap(): void
    {
        $auditCost = AuditCost::of(0, 0, 0.0, 'claude-opus-5', [
            'attacker' => ['model' => 'claude-opus-5', 'input_tokens' => 0, 'output_tokens' => 0, 'estimated_cost_usd' => 0.0],
        ]);

        self::assertTrue($auditCost->hasPublishedPricing());
    }

    /**
     * Cache reads are billed, so a model whose entire spend arrived as cached
     * prompt tokens has still been charged — and priced at zero it is still a
     * pricing gap, even though its fresh input and output are both zero.
     *
     * @throws InvalidAuditCostException
     */
    public function test_has_published_pricing_counts_cached_prompt_tokens_as_spend(): void
    {
        $auditCost = AuditCost::of(0, 0, 0.0, 'ollama/llama3.2')->withUsageByModel([
            'ollama/llama3.2' => ['model' => 'ollama/llama3.2', 'input_tokens' => 0, 'output_tokens' => 0, 'cache_read_tokens' => 4_000, 'cache_creation_tokens' => 1_000, 'estimated_cost_usd' => 0.0],
        ]);

        self::assertFalse($auditCost->hasPublishedPricing());
    }

    /**
     * "Some tokens were spent" is the sum of input and output, not their
     * difference: an entry that happens to spend as many output tokens as
     * input ones is still spend, and must still be checked for a price.
     *
     * @throws InvalidAuditCostException
     */
    public function test_has_published_pricing_counts_input_and_output_tokens_together(): void
    {
        $auditCost = AuditCost::of(2_000, 2_000, 0.0, 'ollama/llama3.2')->withUsageByModel([
            'ollama/llama3.2' => ['model' => 'ollama/llama3.2', 'input_tokens' => 2_000, 'output_tokens' => 2_000, 'estimated_cost_usd' => 0.0],
        ]);

        self::assertFalse($auditCost->hasPublishedPricing());
    }

    /**
     * @throws InvalidAuditCostException
     */
    public function test_has_published_pricing_still_falls_back_to_the_aggregate_without_any_breakdown(): void
    {
        $auditCost = AuditCost::of(120_000, 8_000, 1.87, 'claude-opus-5');

        self::assertTrue($auditCost->hasPublishedPricing());
    }

    /**
     * @throws InvalidAuditCostException
     */
    public function test_has_published_pricing_is_true_when_every_split_role_prices_above_zero(): void
    {
        $auditCost = AuditCost::of(150, 75, 0.05, 'claude-opus-4-7', [
            'attacker' => ['model' => 'claude-opus-4-7', 'input_tokens' => 100, 'output_tokens' => 50, 'estimated_cost_usd' => 0.04],
            'reviewer' => ['model' => 'claude-haiku-4-5-20251001', 'input_tokens' => 50, 'output_tokens' => 25, 'estimated_cost_usd' => 0.01],
        ]);

        self::assertTrue($auditCost->hasPublishedPricing());
    }

    /**
     * @throws InvalidAuditCostException
     */
    public function test_cost_is_rounded_to_six_decimal_places(): void
    {
        $auditCost = AuditCost::of(0, 0, 0.0000005, 'm');

        self::assertSame(0.000001, $auditCost->estimatedCostUsd());
    }

    /**
     * @throws InvalidAuditCostException
     */
    public function test_to_array_emits_canonical_keys(): void
    {
        $auditCost = AuditCost::of(120, 30, 0.04, 'claude-sonnet-4-5');

        self::assertEquals([
            'input_tokens' => 120,
            'output_tokens' => 30,
            'total_tokens' => 150,
            'estimated_cost_usd' => 0.04,
            'primary_model' => 'claude-sonnet-4-5',
            'by_role' => (object) [],
            'by_model' => (object) [],
        ], $auditCost->toArray());
    }

    /**
     * The top-level cost and the dry-run's per-role costs are both rounded to
     * six decimals, so accumulated float noise must not leave one field in the
     * same document reading `0.10491600000000001` while another reads
     * `0.104916`.
     *
     * @throws InvalidAuditCostException
     */
    public function test_to_array_rounds_per_model_cost_to_the_same_precision_as_the_total(): void
    {
        $auditCost = AuditCost::of(1_111, 777, 0.104916, 'claude-opus-5')->withUsageByModel([
            'claude-opus-5' => ['model' => 'claude-opus-5', 'input_tokens' => 1_111, 'output_tokens' => 777, 'estimated_cost_usd' => 0.10491600000000001],
        ]);

        self::assertEquals(
            (object) ['claude-opus-5' => ['model' => 'claude-opus-5', 'input_tokens' => 1_111, 'output_tokens' => 777, 'cache_read_tokens' => 0, 'cache_creation_tokens' => 0, 'estimated_cost_usd' => 0.104916]],
            $auditCost->toArray()['by_model'],
        );
    }

    /**
     * Six decimals, not seven: the same precision `BudgetTracker::costUsdUsed()`
     * and the dry-run's per-role costs use.
     *
     * @throws InvalidAuditCostException
     */
    public function test_to_array_rounds_per_model_cost_to_six_decimals(): void
    {
        $auditCost = AuditCost::of(1, 0, 0.0, 'gemini-flash-lite')->withUsageByModel([
            'gemini-flash-lite' => ['model' => 'gemini-flash-lite', 'input_tokens' => 1, 'output_tokens' => 0, 'estimated_cost_usd' => 0.00000015],
        ]);

        self::assertEquals(
            (object) ['gemini-flash-lite' => ['model' => 'gemini-flash-lite', 'input_tokens' => 1, 'output_tokens' => 0, 'cache_read_tokens' => 0, 'cache_creation_tokens' => 0, 'estimated_cost_usd' => 0.0]],
            $auditCost->toArray()['by_model'],
        );
    }

    /**
     * Rounding is for display only. A model too cheap to register at six
     * decimals is still a priced model, so the published-pricing check must
     * read the unrounded cost or it would call it self-hosted.
     *
     * @throws InvalidAuditCostException
     */
    public function test_a_sub_microdollar_cost_still_counts_as_published_pricing(): void
    {
        $auditCost = AuditCost::of(1, 0, 0.0, 'gemini-flash-lite')->withUsageByModel([
            'gemini-flash-lite' => ['model' => 'gemini-flash-lite', 'input_tokens' => 1, 'output_tokens' => 0, 'estimated_cost_usd' => 0.00000015],
        ]);

        self::assertTrue($auditCost->hasPublishedPricing());
    }

    /**
     * @throws InvalidAuditCostException
     */
    public function test_to_array_carries_per_role_breakdown_when_provided(): void
    {
        $auditCost = AuditCost::of(
            inputTokens: 150,
            outputTokens: 30,
            estimatedCostUsd: 0.04,
            primaryModel: 'claude-opus-4-7',
            byRole: [
                'attacker' => ['model' => 'claude-opus-4-7', 'input_tokens' => 100, 'output_tokens' => 20, 'estimated_cost_usd' => 0.035],
                'reviewer' => ['model' => 'claude-haiku-4-5', 'input_tokens' => 50, 'output_tokens' => 10, 'estimated_cost_usd' => 0.005],
            ],
        );

        $arr = $auditCost->toArray();
        self::assertArrayHasKey('by_role', $arr);

        $byRole = $auditCost->byRole();
        self::assertSame('claude-opus-4-7', $byRole['attacker']['model']);
        self::assertSame('claude-haiku-4-5', $byRole['reviewer']['model']);
        self::assertSame(100, $byRole['attacker']['input_tokens']);
        self::assertSame(50, $byRole['reviewer']['input_tokens']);
    }

    /**
     * @throws InvalidAuditCostException
     */
    public function test_by_role_getter_returns_constructor_payload(): void
    {
        $byRole = [
            'attacker' => ['model' => 'm1', 'input_tokens' => 10, 'output_tokens' => 2, 'estimated_cost_usd' => 0.01],
        ];
        $auditCost = AuditCost::of(10, 2, 0.01, 'm1', $byRole);

        self::assertSame($byRole, $auditCost->byRole());
    }

    /**
     * @throws InvalidAuditCostException
     */
    public function test_negative_input_tokens_rejected(): void
    {
        $this->expectException(InvalidAuditCostException::class);
        AuditCost::of(-1, 0, 0.0, 'm');
    }

    /**
     * @throws InvalidAuditCostException
     */
    public function test_negative_cost_message_reports_the_value_to_six_decimals(): void
    {
        $this->expectException(InvalidAuditCostException::class);
        $this->expectExceptionMessageMatches('/^estimatedCostUsd must be >= 0\.0, got -1\.000000$/');

        AuditCost::of(0, 0, -1.0, 'm');
    }

    /**
     * @throws InvalidAuditCostException
     */
    public function test_negative_output_tokens_rejected(): void
    {
        $this->expectException(InvalidAuditCostException::class);
        AuditCost::of(0, -1, 0.0, 'm');
    }

    /**
     * @throws InvalidAuditCostException
     */
    public function test_negative_cost_rejected(): void
    {
        $this->expectException(InvalidAuditCostException::class);
        AuditCost::of(0, 0, -0.01, 'm');
    }

    /**
     * @throws InvalidAuditCostException
     */
    public function test_nan_cost_rejected(): void
    {
        $this->expectException(InvalidAuditCostException::class);
        AuditCost::of(0, 0, \NAN, 'm');
    }

    /**
     * @throws InvalidAuditCostException
     */
    public function test_infinite_cost_rejected(): void
    {
        $this->expectException(InvalidAuditCostException::class);
        AuditCost::of(0, 0, \INF, 'm');
    }

    public function test_negative_cost_message_formats_the_value_with_a_period_regardless_of_the_process_numeric_locale(): void
    {
        $previousLocale = setlocale(\LC_NUMERIC, '0');
        setlocale(\LC_NUMERIC, 'de_DE.UTF-8');

        try {
            $message = '';
            try {
                AuditCost::of(0, 0, -0.01, 'm');
            } catch (InvalidAuditCostException $invalidAuditCostException) {
                $message = $invalidAuditCostException->getMessage();
            }
        } finally {
            setlocale(\LC_NUMERIC, false !== $previousLocale ? $previousLocale : 'C');
        }

        self::assertStringContainsString('got -0.010000', $message);
    }
}
