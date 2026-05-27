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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\TokenEstimatorInterface;

use function Symfony\Component\String\u;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class CharacterBasedTokenEstimator implements TokenEstimatorInterface
{
    public const float CHARS_PER_TOKEN_CLAUDE = 3.5;

    public const float CHARS_PER_TOKEN_GPT = 4.0;

    public const float CHARS_PER_TOKEN_GEMINI = 3.8;

    public const float CHARS_PER_TOKEN_MISTRAL = 3.7;

    public const float CHARS_PER_TOKEN_LLAMA = 3.6;

    public const float CHARS_PER_TOKEN_DEEPSEEK = 3.4;

    public const float CHARS_PER_TOKEN_DEFAULT = 3.2;

    /**
     * Per-model-prefix character-to-token ratios. Calibrated against
     * each vendor's published tokenizer behavior on English source code.
     * The first prefix that the model name starts with wins, so longer /
     * more specific prefixes should appear first.
     *
     * @var list<array{prefix: string, charsPerToken: float}>
     */
    private const array DEFAULT_RATIOS = [
        ['prefix' => 'claude-', 'charsPerToken' => self::CHARS_PER_TOKEN_CLAUDE],
        ['prefix' => 'gpt-', 'charsPerToken' => self::CHARS_PER_TOKEN_GPT],
        ['prefix' => 'o3', 'charsPerToken' => self::CHARS_PER_TOKEN_GPT],
        ['prefix' => 'o4', 'charsPerToken' => self::CHARS_PER_TOKEN_GPT],
        ['prefix' => 'gemini-', 'charsPerToken' => self::CHARS_PER_TOKEN_GEMINI],
        ['prefix' => 'mistral-', 'charsPerToken' => self::CHARS_PER_TOKEN_MISTRAL],
        ['prefix' => 'codestral-', 'charsPerToken' => self::CHARS_PER_TOKEN_MISTRAL],
        ['prefix' => 'llama-', 'charsPerToken' => self::CHARS_PER_TOKEN_LLAMA],
        ['prefix' => 'llama3', 'charsPerToken' => self::CHARS_PER_TOKEN_LLAMA],
        ['prefix' => 'llama4', 'charsPerToken' => self::CHARS_PER_TOKEN_LLAMA],
        ['prefix' => 'meta-llama', 'charsPerToken' => self::CHARS_PER_TOKEN_LLAMA],
        ['prefix' => 'deepseek-', 'charsPerToken' => self::CHARS_PER_TOKEN_DEEPSEEK],
    ];

    /**
     * @param array<string, float> $charsPerTokenByPrefix optional overrides
     *                                                    keyed by model-name
     *                                                    prefix, e.g.
     *                                                    `['my-tuned-' => 3.8]`.
     *                                                    Custom prefixes are
     *                                                    matched in declaration
     *                                                    order and take
     *                                                    precedence over the
     *                                                    built-in defaults.
     */
    public function __construct(private array $charsPerTokenByPrefix = []) {}

    public function estimateTokens(string $text, string $model): int
    {
        return (int) ceil(mb_strlen($text) / $this->charsPerToken($model));
    }

    private function charsPerToken(string $model): float
    {
        foreach ($this->charsPerTokenByPrefix as $prefix => $ratio) {
            if (u($model)->startsWith($prefix)) {
                return $ratio;
            }
        }

        foreach (self::DEFAULT_RATIOS as $entry) {
            if (u($model)->startsWith($entry['prefix'])) {
                return $entry['charsPerToken'];
            }
        }

        return self::CHARS_PER_TOKEN_DEFAULT;
    }
}
