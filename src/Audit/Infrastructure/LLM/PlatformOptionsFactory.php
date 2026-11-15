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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM;

use Symfony\AI\Platform\PlatformOptions;

/**
 * Builds the per-invocation platform options: temperature, the output token
 * cap and the Anthropic-dialect provider JSON mode that other providers
 * reject. The cap goes out as symfony/ai's canonical `max_output_tokens` to a
 * platform whose bridge translates it, or whose API takes it as is (the
 * Responses API), and as `max_tokens` to a Claude model on any other
 * platform; a platform that knows neither gets none, as an unknown field may
 * be refused. The JSON mode goes only to a platform that can honour it: the
 * Anthropic and Bedrock bridges turn any `response_format` into a JSON schema
 * for Anthropic's structured outputs, empty for a JSON-object mode, which
 * Anthropic has no equivalent of, and Bedrock's Mantle route refuses it
 * outright; a gateway relaying a Claude model through an OpenAI-compatible API
 * passes it on.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class PlatformOptionsFactory
{
    /** @var list<string> */
    private const array PLATFORMS_WITHOUT_A_JSON_OBJECT_MODE = ['anthropic', 'bedrock'];

    /** @var list<string> */
    private const array PLATFORMS_TAKING_THE_CANONICAL_OUTPUT_CAP = [
        'albert', 'amazeeai', 'anthropic', 'bedrock', 'edenai', 'gemini', 'generic', 'lmstudio',
        'mistral', 'openai', 'openresponses', 'openrouter', 'ovh', 'vertexai',
    ];

    public function __construct(
        private string $model,
        private ?float $temperature,
        private bool $providerJsonMode,
        private ?int $maxOutputTokens,
        private ?string $servingPlatform = null,
    ) {}

    /**
     * @return array<string, mixed>
     */
    public function baseOptions(): array
    {
        $options = [];
        if (null !== $this->temperature) {
            $options['temperature'] = $this->temperature;
        }

        if ($this->usesAnthropicOptionDialect() && $this->providerJsonMode && !\in_array($this->servingPlatform, self::PLATFORMS_WITHOUT_A_JSON_OBJECT_MODE, true)) {
            $options['response_format'] = ['type' => 'json_object'];
        }

        $outputCapOption = $this->outputCapOption();
        if (null !== $this->maxOutputTokens && null !== $outputCapOption) {
            $options[$outputCapOption] = $this->maxOutputTokens;
        }

        return $options;
    }

    private function outputCapOption(): ?string
    {
        if (\in_array($this->servingPlatform, self::PLATFORMS_TAKING_THE_CANONICAL_OUTPUT_CAP, true)) {
            return PlatformOptions::MAX_OUTPUT_TOKENS;
        }

        return $this->usesAnthropicOptionDialect() ? 'max_tokens' : null;
    }

    private function usesAnthropicOptionDialect(): bool
    {
        return str_contains($this->model, 'claude');
    }
}
