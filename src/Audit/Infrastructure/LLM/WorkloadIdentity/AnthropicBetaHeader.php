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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\WorkloadIdentity;

/**
 * The `anthropic-beta` header of a request made with a federated access token.
 * Names the betas Anthropic requires of such a request and of the token exchange.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class AnthropicBetaHeader
{
    public const string NAME = 'anthropic-beta';

    public const string OAUTH = 'oauth-2025-04-20';

    public const string OIDC_FEDERATION = 'oidc-federation-2026-04-01';

    private const string LINE_PREFIX = 'anthropic-beta:';

    /**
     * @param array<string> $betas
     */
    public function __construct(private array $betas = []) {}

    /**
     * Reads the header among request headers, in either shape Symfony
     * HttpClient takes and in any letter case, the last one winning as it
     * does there; null when none is named so.
     *
     * @param array<mixed> $headers
     */
    public static function in(array $headers): ?self
    {
        $anthropicBetaHeader = null;
        foreach ($headers as $name => $value) {
            if (self::matches($name, $value)) {
                $anthropicBetaHeader = new self(self::betasIn(self::valueOf($name, $value)));
            }
        }

        return $anthropicBetaHeader;
    }

    /**
     * Whether a request header, keyed by its name or written as one line, is
     * this header.
     */
    public static function matches(int|string $name, mixed $value): bool
    {
        return \is_string($name)
            ? self::NAME === strtolower($name)
            : \is_string($value) && str_starts_with(strtolower($value), self::LINE_PREFIX);
    }

    public function withOAuth(): string
    {
        return implode(',', \in_array(self::OAUTH, $this->betas, true) ? $this->betas : [...$this->betas, self::OAUTH]);
    }

    private static function valueOf(int|string $name, mixed $value): mixed
    {
        return \is_int($name) && \is_string($value) ? substr($value, \strlen(self::LINE_PREFIX)) : $value;
    }

    /**
     * @return array<string>
     */
    private static function betasIn(mixed $value): array
    {
        $betas = [];
        foreach (is_iterable($value) ? $value : [$value] as $line) {
            $betas = [...$betas, ...array_map(trim(...), explode(',', \is_string($line) ? $line : ''))];
        }

        return array_filter($betas, static fn (string $beta): bool => '' !== $beta);
    }
}
