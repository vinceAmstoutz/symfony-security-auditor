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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidRateLimitConfigurationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RiskLevel;

final class BundleConfigurationTest extends TestCase
{
    /**
     * @throws InvalidRateLimitConfigurationException
     */
    public function test_from_array_populates_every_typed_field(): void
    {
        $bundleConfiguration = BundleConfiguration::fromArray($this->treeBuilderOutput());

        self::assertSame('claude-opus-4-7', $bundleConfiguration->llm->attackerModel());
        self::assertSame('claude-haiku-4-5-20251001', $bundleConfiguration->llm->reviewerModel());

        self::assertSame(['src', 'config', 'templates', 'public/index.php'], $bundleConfiguration->scan->includedPaths);
        self::assertTrue($bundleConfiguration->scan->respectGitignore);
        self::assertSame(256, $bundleConfiguration->scan->maxFileSizeKb);
        self::assertTrue($bundleConfiguration->scan->secretScrubbingEnabled);
        self::assertSame([], $bundleConfiguration->scan->additionalScrubberPatterns);
        self::assertSame([], $bundleConfiguration->scan->customRiskPatterns);

        self::assertSame(5, $bundleConfiguration->audit->maxIterations);
        self::assertSame(0.6, $bundleConfiguration->audit->minConfidence);
        self::assertSame(1, $bundleConfiguration->audit->reviewerBatchSize);
        self::assertTrue($bundleConfiguration->audit->toolsEnabled);
        self::assertSame(8, $bundleConfiguration->audit->maxToolIterations);
        self::assertTrue($bundleConfiguration->audit->staticPreScanEnabled);
        self::assertFalse($bundleConfiguration->audit->staticPreScanLeanMode);
        self::assertFalse($bundleConfiguration->audit->reviewerToolsEnabled);
        self::assertSame(4, $bundleConfiguration->audit->reviewerMaxToolIterations);
        self::assertSame(1, $bundleConfiguration->audit->reviewerMaxConcurrent);
        self::assertSame('feature', $bundleConfiguration->audit->chunkingStrategy);
        self::assertFalse($bundleConfiguration->audit->poCSynthesisEnabled);
        self::assertSame('high', $bundleConfiguration->audit->poCSynthesisSeverityFloor);
        self::assertFalse($bundleConfiguration->audit->codeSlicingEnabled);
        self::assertSame(80, $bundleConfiguration->audit->codeSlicingMinLines);
        self::assertFalse($bundleConfiguration->audit->escalationEnabled);
        self::assertNull($bundleConfiguration->audit->escalationCheapModel);
        self::assertSame(RiskLevel::Critical, $bundleConfiguration->audit->failOn);
        self::assertSame([], $bundleConfiguration->audit->excludedTypes);
        self::assertSame([], $bundleConfiguration->audit->includedTypes);

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

    /**
     * @throws InvalidRateLimitConfigurationException
     */
    public function test_from_array_maps_explicit_fail_on_level(): void
    {
        $config = $this->treeBuilderOutput();
        $config['audit']['fail_on'] = 'high';

        $bundleConfiguration = BundleConfiguration::fromArray($config);

        self::assertSame(RiskLevel::High, $bundleConfiguration->audit->failOn);
    }

    /**
     * @throws InvalidRateLimitConfigurationException
     */
    public function test_from_array_defaults_fail_on_to_critical_when_key_omitted_for_bc(): void
    {
        $config = $this->treeBuilderOutput();
        unset($config['audit']['fail_on']);

        $bundleConfiguration = BundleConfiguration::fromArray($config);

        self::assertSame(RiskLevel::Critical, $bundleConfiguration->audit->failOn);
    }

    /**
     * @throws InvalidRateLimitConfigurationException
     */
    public function test_from_array_maps_excluded_and_included_types(): void
    {
        $config = $this->treeBuilderOutput();
        $config['audit']['excluded_types'] = ['missing_rate_limiting', 'log_injection'];
        $config['audit']['included_types'] = ['sql_injection'];

        $bundleConfiguration = BundleConfiguration::fromArray($config);

        self::assertSame(['missing_rate_limiting', 'log_injection'], $bundleConfiguration->audit->excludedTypes);
        self::assertSame(['sql_injection'], $bundleConfiguration->audit->includedTypes);
    }

    /**
     * @throws InvalidRateLimitConfigurationException
     */
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

    /**
     * @throws InvalidRateLimitConfigurationException
     */
    public function test_attacker_model_falls_back_to_top_level_model_when_override_omitted(): void
    {
        $config = $this->treeBuilderOutput();
        $config['attacker_model'] = null;

        $bundleConfiguration = BundleConfiguration::fromArray($config);

        self::assertSame('claude-opus-4-7', $bundleConfiguration->llm->attackerModel());
    }

    /**
     * @throws InvalidRateLimitConfigurationException
     */
    public function test_reviewer_model_falls_back_to_top_level_model_when_override_omitted(): void
    {
        $config = $this->treeBuilderOutput();
        $config['reviewer_model'] = null;

        $bundleConfiguration = BundleConfiguration::fromArray($config);

        self::assertSame('claude-opus-4-7', $bundleConfiguration->llm->reviewerModel());
    }

    /**
     * @throws InvalidRateLimitConfigurationException
     */
    public function test_max_output_tokens_defaults_flow_through_to_both_agents_when_overrides_omitted(): void
    {
        $bundleConfiguration = BundleConfiguration::fromArray($this->treeBuilderOutput());

        self::assertSame(4096, $bundleConfiguration->llm->attackerMaxOutputTokens());
        self::assertSame(4096, $bundleConfiguration->llm->reviewerMaxOutputTokens());
    }

    /**
     * @throws InvalidRateLimitConfigurationException
     */
    public function test_max_output_tokens_overrides_flow_through_per_agent(): void
    {
        $config = $this->treeBuilderOutput();
        $config['attacker_max_output_tokens'] = 8192;
        $config['reviewer_max_output_tokens'] = 2048;

        $bundleConfiguration = BundleConfiguration::fromArray($config);

        self::assertSame(8192, $bundleConfiguration->llm->attackerMaxOutputTokens());
        self::assertSame(2048, $bundleConfiguration->llm->reviewerMaxOutputTokens());
    }

    /**
     * @throws InvalidRateLimitConfigurationException
     */
    public function test_attacker_max_output_tokens_falls_back_to_top_level_when_override_omitted(): void
    {
        $config = $this->treeBuilderOutput();
        $config['max_output_tokens'] = 6000;
        $config['attacker_max_output_tokens'] = null;
        $config['reviewer_max_output_tokens'] = null;

        $bundleConfiguration = BundleConfiguration::fromArray($config);

        self::assertSame(6000, $bundleConfiguration->llm->attackerMaxOutputTokens());
        self::assertSame(6000, $bundleConfiguration->llm->reviewerMaxOutputTokens());
    }

    /**
     * @throws InvalidRateLimitConfigurationException
     */
    public function test_budget_is_not_unlimited_when_token_cap_set(): void
    {
        $config = $this->treeBuilderOutput();
        $config['audit']['budget']['max_tokens'] = 50_000;

        $bundleConfiguration = BundleConfiguration::fromArray($config);

        self::assertFalse($bundleConfiguration->budget->isUnlimited());
        self::assertSame(50_000, $bundleConfiguration->budget->maxTokens);
    }

    /**
     * @throws InvalidRateLimitConfigurationException
     */
    public function test_provider_json_mode_defaults_false_in_tree_output(): void
    {
        $bundleConfiguration = BundleConfiguration::fromArray($this->treeBuilderOutput());

        self::assertFalse($bundleConfiguration->llm->providerJsonMode);
    }

    /**
     * @throws InvalidRateLimitConfigurationException
     */
    public function test_provider_json_mode_flows_through_when_enabled(): void
    {
        $config = $this->treeBuilderOutput();
        $config['provider_json_mode'] = true;

        $bundleConfiguration = BundleConfiguration::fromArray($config);

        self::assertTrue($bundleConfiguration->llm->providerJsonMode);
    }

    /**
     * @throws InvalidRateLimitConfigurationException
     */
    public function test_from_array_tolerates_omitted_provider_json_mode_key_for_bc(): void
    {
        $config = $this->treeBuilderOutput();
        unset($config['provider_json_mode']);

        $bundleConfiguration = BundleConfiguration::fromArray($config);

        self::assertFalse($bundleConfiguration->llm->providerJsonMode);
    }

    /**
     * @throws InvalidRateLimitConfigurationException
     */
    public function test_from_array_defaults_max_output_tokens_to_4096_when_key_omitted_for_bc(): void
    {
        $config = $this->treeBuilderOutput();
        unset($config['max_output_tokens'], $config['attacker_max_output_tokens'], $config['reviewer_max_output_tokens']);

        $bundleConfiguration = BundleConfiguration::fromArray($config);

        self::assertSame(4096, $bundleConfiguration->llm->attackerMaxOutputTokens());
        self::assertSame(4096, $bundleConfiguration->llm->reviewerMaxOutputTokens());
    }

    /**
     * @throws InvalidRateLimitConfigurationException
     */
    public function test_from_array_defaults_structured_collection_to_true_when_audit_key_omits_it(): void
    {
        $config = $this->treeBuilderOutput();
        unset($config['audit']['structured_collection']);

        $bundleConfiguration = BundleConfiguration::fromArray($config);

        self::assertTrue($bundleConfiguration->audit->structuredCollection);
    }

    /**
     * @throws InvalidRateLimitConfigurationException
     */
    public function test_from_array_propagates_structured_collection_opt_out(): void
    {
        $config = $this->treeBuilderOutput();
        $config['audit']['structured_collection'] = false;

        $bundleConfiguration = BundleConfiguration::fromArray($config);

        self::assertFalse($bundleConfiguration->audit->structuredCollection);
    }

    /**
     * @throws InvalidRateLimitConfigurationException
     */
    public function test_from_array_defaults_reviewer_structured_collection_to_true_when_audit_key_omits_it(): void
    {
        $config = $this->treeBuilderOutput();
        unset($config['audit']['reviewer_structured_collection']);

        $bundleConfiguration = BundleConfiguration::fromArray($config);

        self::assertTrue($bundleConfiguration->audit->reviewerStructuredCollection);
    }

    /**
     * @throws InvalidRateLimitConfigurationException
     */
    public function test_from_array_propagates_reviewer_structured_collection_opt_out(): void
    {
        $config = $this->treeBuilderOutput();
        $config['audit']['reviewer_structured_collection'] = false;

        $bundleConfiguration = BundleConfiguration::fromArray($config);

        self::assertFalse($bundleConfiguration->audit->reviewerStructuredCollection);
    }

    /**
     * @throws InvalidRateLimitConfigurationException
     */
    public function test_from_array_defaults_stable_system_prompt_to_true_when_audit_key_omits_it(): void
    {
        $config = $this->treeBuilderOutput();
        unset($config['audit']['stable_system_prompt']);

        $bundleConfiguration = BundleConfiguration::fromArray($config);

        self::assertTrue($bundleConfiguration->audit->stableSystemPrompt);
    }

    /**
     * @throws InvalidRateLimitConfigurationException
     */
    public function test_from_array_propagates_stable_system_prompt_opt_out(): void
    {
        $config = $this->treeBuilderOutput();
        $config['audit']['stable_system_prompt'] = false;

        $bundleConfiguration = BundleConfiguration::fromArray($config);

        self::assertFalse($bundleConfiguration->audit->stableSystemPrompt);
    }

    /**
     * @throws InvalidRateLimitConfigurationException
     */
    public function test_from_array_resolves_fast_profile_for_unset_keys(): void
    {
        $config = $this->profileShapedConfig('fast');

        $bundleConfiguration = BundleConfiguration::fromArray($config);

        self::assertSame(1, $bundleConfiguration->audit->maxIterations);
        self::assertTrue($bundleConfiguration->audit->staticPreScanLeanMode);
        self::assertTrue($bundleConfiguration->audit->codeSlicingEnabled);
        self::assertFalse($bundleConfiguration->audit->poCSynthesisEnabled);
        self::assertSame(4, $bundleConfiguration->audit->reviewerMaxConcurrent);
        self::assertSame(4, $bundleConfiguration->audit->attackerMaxConcurrent);
    }

    /**
     * @throws InvalidRateLimitConfigurationException
     */
    public function test_from_array_resolves_thorough_profile_for_unset_keys(): void
    {
        $config = $this->profileShapedConfig('thorough');

        $bundleConfiguration = BundleConfiguration::fromArray($config);

        self::assertSame(3, $bundleConfiguration->audit->maxIterations);
        self::assertFalse($bundleConfiguration->audit->staticPreScanLeanMode);
        self::assertFalse($bundleConfiguration->audit->codeSlicingEnabled);
        self::assertTrue($bundleConfiguration->audit->poCSynthesisEnabled);
        self::assertSame(1, $bundleConfiguration->audit->reviewerMaxConcurrent);
        self::assertSame(1, $bundleConfiguration->audit->attackerMaxConcurrent);
    }

    /**
     * @throws InvalidRateLimitConfigurationException
     */
    public function test_from_array_defaults_to_the_balanced_profile_when_the_key_is_absent(): void
    {
        $config = $this->profileShapedConfig(null);
        unset($config['profile']);

        $bundleConfiguration = BundleConfiguration::fromArray($config);

        self::assertSame(3, $bundleConfiguration->audit->maxIterations);
        self::assertFalse($bundleConfiguration->audit->staticPreScanLeanMode);
        self::assertFalse($bundleConfiguration->audit->codeSlicingEnabled);
        self::assertFalse($bundleConfiguration->audit->poCSynthesisEnabled);
        self::assertSame(1, $bundleConfiguration->audit->reviewerMaxConcurrent);
    }

    /**
     * @throws InvalidRateLimitConfigurationException
     */
    public function test_from_array_lets_an_explicit_key_override_the_profile(): void
    {
        $config = $this->profileShapedConfig('fast');
        $config['audit']['max_iterations'] = 2;
        $config['audit']['reviewer_max_concurrent'] = 1;

        $bundleConfiguration = BundleConfiguration::fromArray($config);

        self::assertSame(2, $bundleConfiguration->audit->maxIterations);
        self::assertSame(1, $bundleConfiguration->audit->reviewerMaxConcurrent);
        self::assertTrue($bundleConfiguration->audit->staticPreScanLeanMode);
    }

    /**
     * @throws InvalidRateLimitConfigurationException
     */
    public function test_from_array_lets_explicit_boolean_keys_override_the_profile(): void
    {
        $config = $this->profileShapedConfig('fast');
        $config['audit']['static_prescan']['lean_mode'] = false;
        $config['audit']['code_slicing']['enabled'] = false;
        $config['audit']['poc_synthesis']['enabled'] = true;

        $bundleConfiguration = BundleConfiguration::fromArray($config);

        self::assertFalse($bundleConfiguration->audit->staticPreScanLeanMode);
        self::assertFalse($bundleConfiguration->audit->codeSlicingEnabled);
        self::assertTrue($bundleConfiguration->audit->poCSynthesisEnabled);
    }

    /**
     * @return array{
     *     profile?: string,
     *     model: string,
     *     attacker_model: string|null,
     *     reviewer_model: string|null,
     *     max_output_tokens?: int,
     *     attacker_max_output_tokens?: int|null,
     *     reviewer_max_output_tokens?: int|null,
     *     provider_json_mode?: bool,
     *     scan: array{included_paths: list<string>, respect_gitignore: bool, max_file_size_kb: int, custom_risk_patterns: array<string, array<string, array{regex: string, description: string}>>, secret_scrubbing: array{enabled: bool, additional_patterns: list<string>}},
     *     audit: array{max_iterations: int|null, min_confidence: float, reviewer_batch_size: int, tools_enabled: bool, structured_collection?: bool, reviewer_structured_collection?: bool, stable_system_prompt?: bool, max_tool_iterations: int, reviewer_tools_enabled: bool, reviewer_max_tool_iterations: int, fail_on?: string, reviewer_max_concurrent: int|null, attacker_max_concurrent: int|null, static_prescan: array{enabled: bool, lean_mode: bool|null}, chunking: array{strategy: string}, poc_synthesis: array{enabled: bool|null, severity_floor: string}, code_slicing: array{enabled: bool|null, min_lines_before_slicing: int}, escalation: array{enabled: bool, cheap_model: string|null}, budget: array{max_tokens: int|null, max_cost_usd: float|null}, retry: array{max_attempts: int, initial_delay_ms: int, backoff_multiplier: float, jitter_ratio: float}, rate_limit: array{requests_per_minute: int|null, input_tokens_per_minute: int|null, output_tokens_per_minute: int|null}},
     *     cache: array{enabled: bool, dir: string, prompt_caching: bool},
     * }
     */
    private function profileShapedConfig(?string $profile): array
    {
        $config = $this->treeBuilderOutput();
        if (null !== $profile) {
            $config['profile'] = $profile;
        }

        $config['audit']['max_iterations'] = null;
        $config['audit']['reviewer_max_concurrent'] = null;
        $config['audit']['attacker_max_concurrent'] = null;
        $config['audit']['static_prescan']['lean_mode'] = null;
        $config['audit']['code_slicing']['enabled'] = null;
        $config['audit']['poc_synthesis']['enabled'] = null;

        return $config;
    }

    /**
     * @return array{
     *     profile?: string,
     *     model: string,
     *     attacker_model: string|null,
     *     reviewer_model: string|null,
     *     max_output_tokens?: int,
     *     attacker_max_output_tokens?: int|null,
     *     reviewer_max_output_tokens?: int|null,
     *     provider_json_mode?: bool,
     *     scan: array{included_paths: list<string>, respect_gitignore: bool, max_file_size_kb: int, custom_risk_patterns: array<string, array<string, array{regex: string, description: string}>>, secret_scrubbing: array{enabled: bool, additional_patterns: list<string>}},
     *     audit: array{max_iterations: int|null, min_confidence: float, reviewer_batch_size: int, tools_enabled: bool, structured_collection?: bool, reviewer_structured_collection?: bool, stable_system_prompt?: bool, max_tool_iterations: int, reviewer_tools_enabled: bool, reviewer_max_tool_iterations: int, fail_on?: string, reviewer_max_concurrent: int|null, attacker_max_concurrent: int|null, static_prescan: array{enabled: bool, lean_mode: bool|null}, chunking: array{strategy: string}, poc_synthesis: array{enabled: bool|null, severity_floor: string}, code_slicing: array{enabled: bool|null, min_lines_before_slicing: int}, escalation: array{enabled: bool, cheap_model: string|null}, budget: array{max_tokens: int|null, max_cost_usd: float|null}, retry: array{max_attempts: int, initial_delay_ms: int, backoff_multiplier: float, jitter_ratio: float}, rate_limit: array{requests_per_minute: int|null, input_tokens_per_minute: int|null, output_tokens_per_minute: int|null}},
     *     cache: array{enabled: bool, dir: string, prompt_caching: bool},
     * }
     */
    private function treeBuilderOutput(): array
    {
        return [
            'model' => 'claude-opus-4-7',
            'attacker_model' => null,
            'reviewer_model' => 'claude-haiku-4-5-20251001',
            'max_output_tokens' => 4096,
            'attacker_max_output_tokens' => null,
            'reviewer_max_output_tokens' => null,
            'provider_json_mode' => false,
            'scan' => [
                'included_paths' => ['src', 'config', 'templates', 'public/index.php'],
                'respect_gitignore' => true,
                'max_file_size_kb' => 256,
                'secret_scrubbing' => [
                    'enabled' => true,
                    'additional_patterns' => [],
                ],
                'custom_risk_patterns' => [],
            ],
            'audit' => [
                'max_iterations' => 5,
                'min_confidence' => 0.6,
                'reviewer_batch_size' => 1,
                'tools_enabled' => true,
                'max_tool_iterations' => 8,
                'static_prescan' => [
                    'enabled' => true,
                    'lean_mode' => false,
                ],
                'reviewer_tools_enabled' => false,
                'reviewer_max_tool_iterations' => 4,
                'reviewer_max_concurrent' => 1,
                'attacker_max_concurrent' => 1,
                'chunking' => [
                    'strategy' => 'feature',
                ],
                'poc_synthesis' => [
                    'enabled' => false,
                    'severity_floor' => 'high',
                ],
                'code_slicing' => [
                    'enabled' => false,
                    'min_lines_before_slicing' => 80,
                ],
                'escalation' => [
                    'enabled' => false,
                    'cheap_model' => null,
                ],
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
