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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Domain\Configuration;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Configuration\BundleConfiguration;

final class BundleConfigurationTest extends TestCase
{
    public function test_from_array_populates_every_typed_field(): void
    {
        $bundleConfiguration = BundleConfiguration::fromArray($this->treeBuilderOutput());

        self::assertSame('claude-opus-4-7', $bundleConfiguration->llm->attackerModel());
        self::assertSame('claude-haiku-4-5-20251001', $bundleConfiguration->llm->reviewerModel());

        self::assertSame(['legacy'], $bundleConfiguration->scan->excludedDirs);
        self::assertTrue($bundleConfiguration->scan->respectGitignore);
        self::assertSame(256, $bundleConfiguration->scan->maxFileSizeKb);
        self::assertTrue($bundleConfiguration->scan->secretScrubbingEnabled);
        self::assertSame([], $bundleConfiguration->scan->additionalScrubberPatterns);

        self::assertSame(5, $bundleConfiguration->audit->maxIterations);
        self::assertSame(0.6, $bundleConfiguration->audit->minConfidence);
        self::assertSame(1, $bundleConfiguration->audit->reviewerBatchSize);
        self::assertTrue($bundleConfiguration->audit->toolsEnabled);
        self::assertSame(8, $bundleConfiguration->audit->maxToolIterations);

        self::assertSame(3, $bundleConfiguration->retry->maxAttempts);
        self::assertSame(500, $bundleConfiguration->retry->initialDelayMs);
        self::assertSame(2.0, $bundleConfiguration->retry->backoffMultiplier);
        self::assertSame(0.2, $bundleConfiguration->retry->jitterRatio);

        self::assertNull($bundleConfiguration->budget->maxTokens);
        self::assertNull($bundleConfiguration->budget->maxCostUsd);
        self::assertTrue($bundleConfiguration->budget->isUnlimited());

        self::assertTrue($bundleConfiguration->cache->enabled);
        self::assertSame('/cache', $bundleConfiguration->cache->dir);
        self::assertTrue($bundleConfiguration->cache->promptCaching);

        self::assertNull($bundleConfiguration->rateLimit->requestsPerMinute);
        self::assertNull($bundleConfiguration->rateLimit->inputTokensPerMinute);
        self::assertNull($bundleConfiguration->rateLimit->outputTokensPerMinute);
        self::assertFalse($bundleConfiguration->rateLimit->isEnabled());
    }

    public function test_rate_limit_dimensions_flow_through_when_set(): void
    {
        $config = $this->treeBuilderOutput();
        $config['audit']['rate_limit'] = [
            'requests_per_minute' => 50,
            'input_tokens_per_minute' => 50_000,
            'output_tokens_per_minute' => 10_000,
        ];

        $bundleConfiguration = BundleConfiguration::fromArray($config);

        self::assertSame(50, $bundleConfiguration->rateLimit->requestsPerMinute);
        self::assertSame(50_000, $bundleConfiguration->rateLimit->inputTokensPerMinute);
        self::assertSame(10_000, $bundleConfiguration->rateLimit->outputTokensPerMinute);
        self::assertTrue($bundleConfiguration->rateLimit->isEnabled());
    }

    public function test_attacker_model_falls_back_to_top_level_model_when_override_omitted(): void
    {
        $config = $this->treeBuilderOutput();
        $config['attacker_model'] = null;

        $bundleConfiguration = BundleConfiguration::fromArray($config);

        self::assertSame('claude-opus-4-7', $bundleConfiguration->llm->attackerModel());
    }

    public function test_reviewer_model_falls_back_to_top_level_model_when_override_omitted(): void
    {
        $config = $this->treeBuilderOutput();
        $config['reviewer_model'] = null;

        $bundleConfiguration = BundleConfiguration::fromArray($config);

        self::assertSame('claude-opus-4-7', $bundleConfiguration->llm->reviewerModel());
    }

    public function test_budget_is_not_unlimited_when_token_cap_set(): void
    {
        $config = $this->treeBuilderOutput();
        $config['audit']['budget']['max_tokens'] = 50_000;

        $bundleConfiguration = BundleConfiguration::fromArray($config);

        self::assertFalse($bundleConfiguration->budget->isUnlimited());
        self::assertSame(50_000, $bundleConfiguration->budget->maxTokens);
    }

    public function test_provider_json_mode_defaults_false_in_tree_output(): void
    {
        $bundleConfiguration = BundleConfiguration::fromArray($this->treeBuilderOutput());

        self::assertFalse($bundleConfiguration->llm->providerJsonMode);
    }

    public function test_provider_json_mode_flows_through_when_enabled(): void
    {
        $config = $this->treeBuilderOutput();
        $config['provider_json_mode'] = true;

        $bundleConfiguration = BundleConfiguration::fromArray($config);

        self::assertTrue($bundleConfiguration->llm->providerJsonMode);
    }

    public function test_from_array_tolerates_omitted_provider_json_mode_key_for_bc(): void
    {
        // BC guard: callers that built their array against the 1.0 shape (no
        // provider_json_mode key) must keep working. fromArray must default
        // the missing key to false rather than warning about an undefined index.
        $config = $this->treeBuilderOutput();
        unset($config['provider_json_mode']);

        $bundleConfiguration = BundleConfiguration::fromArray($config);

        self::assertFalse($bundleConfiguration->llm->providerJsonMode);
    }

    /**
     * @return array{
     *     model: string,
     *     attacker_model: string|null,
     *     reviewer_model: string|null,
     *     provider_json_mode: bool,
     *     scan: array{excluded_dirs: list<string>, respect_gitignore: bool, max_file_size_kb: int, secret_scrubbing: array{enabled: bool, additional_patterns: list<string>}},
     *     audit: array{max_iterations: int, min_confidence: float, reviewer_batch_size: int, tools_enabled: bool, max_tool_iterations: int, budget: array{max_tokens: int|null, max_cost_usd: float|null}, retry: array{max_attempts: int, initial_delay_ms: int, backoff_multiplier: float, jitter_ratio: float}, rate_limit: array{requests_per_minute: int|null, input_tokens_per_minute: int|null, output_tokens_per_minute: int|null}},
     *     cache: array{enabled: bool, dir: string, prompt_caching: bool},
     * }
     */
    private function treeBuilderOutput(): array
    {
        return [
            'model' => 'claude-opus-4-7',
            'attacker_model' => null,
            'reviewer_model' => 'claude-haiku-4-5-20251001',
            'provider_json_mode' => false,
            'scan' => [
                'excluded_dirs' => ['legacy'],
                'respect_gitignore' => true,
                'max_file_size_kb' => 256,
                'secret_scrubbing' => [
                    'enabled' => true,
                    'additional_patterns' => [],
                ],
            ],
            'audit' => [
                'max_iterations' => 5,
                'min_confidence' => 0.6,
                'reviewer_batch_size' => 1,
                'tools_enabled' => true,
                'max_tool_iterations' => 8,
                'budget' => [
                    'max_tokens' => null,
                    'max_cost_usd' => null,
                ],
                'retry' => [
                    'max_attempts' => 3,
                    'initial_delay_ms' => 500,
                    'backoff_multiplier' => 2.0,
                    'jitter_ratio' => 0.2,
                ],
                'rate_limit' => [
                    'requests_per_minute' => null,
                    'input_tokens_per_minute' => null,
                    'output_tokens_per_minute' => null,
                ],
            ],
            'cache' => [
                'enabled' => true,
                'dir' => '/cache',
                'prompt_caching' => true,
            ],
        ];
    }
}
