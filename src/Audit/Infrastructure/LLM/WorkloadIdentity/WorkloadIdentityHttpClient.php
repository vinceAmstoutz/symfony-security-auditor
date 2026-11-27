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

use Override;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Symfony\Contracts\HttpClient\ResponseInterface;
use Symfony\Contracts\HttpClient\ResponseStreamInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\RefusedTokenExchangeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\TransientHttpStatusException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\UnobtainableIdentityTokenException;

/**
 * Sends each request with an access token from workload identity federation
 * as `Authorization: Bearer`, in place of the `x-api-key` header. Adds the
 * OAuth beta Anthropic requires of such a token to the `anthropic-beta` header.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class WorkloadIdentityHttpClient implements HttpClientInterface
{
    private const string API_KEY_HEADER = 'x-api-key';

    public function __construct(
        private HttpClientInterface $httpClient,
        private AccessTokenProviderInterface $accessTokenProvider,
        private AnthropicBetaHeader $defaultAnthropicBetaHeader = new AnthropicBetaHeader(),
    ) {}

    /**
     * @param array<mixed> $options
     *
     * @throws RefusedTokenExchangeException      when the exchange is refused, or answers without an access token
     * @throws TransientHttpStatusException       when the token endpoint answers with a status worth retrying
     * @throws UnobtainableIdentityTokenException when the workload gets no identity token
     */
    #[Override]
    public function request(string $method, string $url, array $options = []): ResponseInterface
    {
        return $this->httpClient->request($method, $url, [...$options, 'headers' => $this->withBearerToken($this->headersIn($options))]);
    }

    #[Override]
    public function stream(iterable|ResponseInterface $responses, ?float $timeout = null): ResponseStreamInterface
    {
        return $this->httpClient->stream($responses, $timeout);
    }

    /**
     * @param array<mixed> $options
     */
    #[Override]
    public function withOptions(array $options): static
    {
        return new self(
            $this->httpClient->withOptions($options),
            $this->accessTokenProvider,
            AnthropicBetaHeader::in($this->headersIn($options)) ?? $this->defaultAnthropicBetaHeader,
        );
    }

    /**
     * @param array<mixed> $options
     *
     * @return array<mixed>
     */
    private function headersIn(array $options): array
    {
        return \is_array($options['headers'] ?? null) ? $options['headers'] : [];
    }

    /**
     * @param array<mixed> $headers
     *
     * @return array<int|string, mixed>
     *
     * @throws RefusedTokenExchangeException      when the exchange is refused, or answers without an access token
     * @throws TransientHttpStatusException       when the token endpoint answers with a status worth retrying
     * @throws UnobtainableIdentityTokenException when the workload gets no identity token
     */
    private function withBearerToken(array $headers): array
    {
        $kept = [];
        foreach ($headers as $name => $value) {
            if (!$this->isApiKey($name) && !AnthropicBetaHeader::matches($name, $value)) {
                $kept[$name] = $value;
            }
        }

        $kept[AnthropicBetaHeader::NAME] = (AnthropicBetaHeader::in($headers) ?? $this->defaultAnthropicBetaHeader)->withOAuth();
        $kept['authorization'] = \sprintf('Bearer %s', $this->accessTokenProvider->accessToken());

        return $kept;
    }

    private function isApiKey(mixed $name): bool
    {
        return \is_string($name) && self::API_KEY_HEADER === strtolower($name);
    }
}
