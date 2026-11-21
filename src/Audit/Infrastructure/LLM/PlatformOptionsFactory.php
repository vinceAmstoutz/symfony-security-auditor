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
 * Builds the per-invocation platform options: temperature, and the
 * Anthropic-dialect output token cap and provider JSON mode that other
 * providers reject. The cap goes to a Claude model only, as symfony/ai's
 * canonical `max_output_tokens` on a platform whose bridge translates it and
 * as `max_tokens` elsewhere: on another model it would also count the
 * reasoning tokens and cut a thinking model's answer short. The JSON mode goes only to a platform that can honour it: the
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
        if (!$this->usesAnthropicOptionDialect()) {
            return null;
        }

        return \in_array($this->servingPlatform, self::PLATFORMS_TAKING_THE_CANONICAL_OUTPUT_CAP, true) ? PlatformOptions::MAX_OUTPUT_TOKENS : 'max_tokens';
    }

    private function usesAnthropicOptionDialect(): bool
    {
        return str_contains($this->model, 'claude');
    }
}
