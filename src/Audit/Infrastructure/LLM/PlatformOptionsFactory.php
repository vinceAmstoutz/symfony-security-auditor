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
 * Builds the platform options of a call: the temperature and, for a Claude
 * model only, the output cap and the provider JSON mode. The cap goes as
 * `max_output_tokens` where the bridge translates it, as `max_tokens`
 * elsewhere; on another model it would also count the reasoning tokens. The
 * JSON mode never goes to the Anthropic or Bedrock platform, whose bridges
 * turn it into an empty JSON schema or refuse it.
 *
 * @internal not part of the BC promise, see docs/versioning.md
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
