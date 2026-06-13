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

/**
 * Builds the per-invocation platform options: temperature plus the
 * Anthropic-dialect knobs (provider JSON mode, max output tokens) that other
 * providers reject.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class PlatformOptionsFactory
{
    public function __construct(
        private string $model,
        private ?float $temperature,
        private bool $providerJsonMode,
        private ?int $maxOutputTokens,
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

        if ($this->usesAnthropicOptionDialect()) {
            if ($this->providerJsonMode) {
                $options['response_format'] = ['type' => 'json_object'];
            }

            if (null !== $this->maxOutputTokens) {
                $options['max_tokens'] = $this->maxOutputTokens;
            }
        }

        return $options;
    }

    private function usesAnthropicOptionDialect(): bool
    {
        return str_contains($this->model, 'claude');
    }
}
