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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\LLM\WorkloadIdentity;

use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\RefusedTokenExchangeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\TransientHttpStatusException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\UnobtainableIdentityTokenException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\WorkloadIdentity\AccessTokenProviderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\WorkloadIdentity\WorkloadIdentityHttpClient;

final class WorkloadIdentityHttpClientTest extends TestCase
{
    /**
     * @throws RefusedTokenExchangeException
     * @throws TransientHttpStatusException
     * @throws UnobtainableIdentityTokenException
     */
    public function test_it_sends_the_federated_access_token_as_a_bearer_token_in_place_of_the_api_key(): void
    {
        $mockResponse = new MockResponse('{}');
        $accessTokenProvider = self::createStub(AccessTokenProviderInterface::class);
        $accessTokenProvider->method('accessToken')->willReturn('sk-ant-oat01-federated');

        (new WorkloadIdentityHttpClient(new MockHttpClient($mockResponse), $accessTokenProvider))
            ->request('POST', 'https://api.anthropic.com/v1/messages', ['headers' => ['x-api-key' => 'unused', 'anthropic-version' => '2023-06-01']]);

        self::assertSame(
            ['anthropic-version' => ['anthropic-version: 2023-06-01'], 'authorization' => ['authorization: Bearer sk-ant-oat01-federated']],
            array_intersect_key($this->sentHeaders($mockResponse), ['authorization' => true, 'x-api-key' => true, 'anthropic-version' => true]),
        );
    }

    /**
     * @throws RefusedTokenExchangeException
     * @throws TransientHttpStatusException
     * @throws UnobtainableIdentityTokenException
     */
    public function test_it_asks_for_the_oauth_beta_the_bearer_token_needs(): void
    {
        $mockResponse = new MockResponse('{}');

        (new WorkloadIdentityHttpClient(new MockHttpClient($mockResponse), $this->accessTokenProvider()))
            ->request('POST', 'https://api.anthropic.com/v1/messages', ['headers' => ['anthropic-version' => '2023-06-01']]);

        self::assertSame(['anthropic-beta: oauth-2025-04-20'], $this->sentHeaders($mockResponse)['anthropic-beta'] ?? null);
    }

    /**
     * @throws RefusedTokenExchangeException
     * @throws TransientHttpStatusException
     * @throws UnobtainableIdentityTokenException
     */
    public function test_it_adds_the_oauth_beta_to_the_betas_the_request_asks_for(): void
    {
        $mockResponse = new MockResponse('{}');

        (new WorkloadIdentityHttpClient(new MockHttpClient($mockResponse), $this->accessTokenProvider()))
            ->request('POST', 'https://api.anthropic.com/v1/messages', ['headers' => ['anthropic-beta' => 'interleaved-thinking-2025-05-14']]);

        self::assertSame(['anthropic-beta: interleaved-thinking-2025-05-14,oauth-2025-04-20'], $this->sentHeaders($mockResponse)['anthropic-beta'] ?? null);
    }

    /**
     * @throws RefusedTokenExchangeException
     * @throws TransientHttpStatusException
     * @throws UnobtainableIdentityTokenException
     */
    public function test_it_adds_the_oauth_beta_to_a_beta_header_whatever_its_case(): void
    {
        $mockResponse = new MockResponse('{}');

        (new WorkloadIdentityHttpClient(new MockHttpClient($mockResponse), $this->accessTokenProvider()))
            ->request('POST', 'https://api.anthropic.com/v1/messages', ['headers' => ['Anthropic-Beta' => 'files-api']]);

        self::assertSame(['anthropic-beta: files-api,oauth-2025-04-20'], $this->sentHeaders($mockResponse)['anthropic-beta'] ?? null);
    }

    /**
     * @throws RefusedTokenExchangeException
     * @throws TransientHttpStatusException
     * @throws UnobtainableIdentityTokenException
     */
    public function test_it_asks_for_the_oauth_beta_once_when_the_request_already_does(): void
    {
        $mockResponse = new MockResponse('{}');

        (new WorkloadIdentityHttpClient(new MockHttpClient($mockResponse), $this->accessTokenProvider()))
            ->request('POST', 'https://api.anthropic.com/v1/messages', ['headers' => ['anthropic-beta' => 'oauth-2025-04-20, files-api']]);

        self::assertSame(['anthropic-beta: oauth-2025-04-20,files-api'], $this->sentHeaders($mockResponse)['anthropic-beta'] ?? null);
    }

    /**
     * @throws RefusedTokenExchangeException
     * @throws TransientHttpStatusException
     * @throws UnobtainableIdentityTokenException
     */
    public function test_it_adds_the_oauth_beta_to_a_beta_header_given_several_values(): void
    {
        $mockResponse = new MockResponse('{}');

        (new WorkloadIdentityHttpClient(new MockHttpClient($mockResponse), $this->accessTokenProvider()))
            ->request('POST', 'https://api.anthropic.com/v1/messages', ['headers' => ['anthropic-beta' => ['files-api', 'interleaved-thinking-2025-05-14']]]);

        self::assertSame(['anthropic-beta: files-api,interleaved-thinking-2025-05-14,oauth-2025-04-20'], $this->sentHeaders($mockResponse)['anthropic-beta'] ?? null);
    }

    /**
     * @throws RefusedTokenExchangeException
     * @throws TransientHttpStatusException
     * @throws UnobtainableIdentityTokenException
     */
    public function test_it_asks_for_the_oauth_beta_alone_in_place_of_an_empty_beta_header(): void
    {
        $mockResponse = new MockResponse('{}');

        (new WorkloadIdentityHttpClient(new MockHttpClient($mockResponse), $this->accessTokenProvider()))
            ->request('POST', 'https://api.anthropic.com/v1/messages', ['headers' => ['anthropic-beta' => ' , ']]);

        self::assertSame(['anthropic-beta: oauth-2025-04-20'], $this->sentHeaders($mockResponse)['anthropic-beta'] ?? null);
    }

    /**
     * @throws RefusedTokenExchangeException
     * @throws TransientHttpStatusException
     * @throws UnobtainableIdentityTokenException
     */
    public function test_the_last_beta_header_of_the_request_wins_as_it_does_without_the_bearer_token(): void
    {
        $mockResponse = new MockResponse('{}');

        (new WorkloadIdentityHttpClient(new MockHttpClient($mockResponse), $this->accessTokenProvider()))
            ->request('POST', 'https://api.anthropic.com/v1/messages', ['headers' => ['anthropic-beta' => 'files-api', 'ANTHROPIC-BETA: interleaved-thinking-2025-05-14']]);

        self::assertSame(['anthropic-beta: interleaved-thinking-2025-05-14,oauth-2025-04-20'], $this->sentHeaders($mockResponse)['anthropic-beta'] ?? null);
    }

    /**
     * @throws RefusedTokenExchangeException
     * @throws TransientHttpStatusException
     * @throws UnobtainableIdentityTokenException
     */
    public function test_it_drops_the_api_key_header_whatever_its_case(): void
    {
        $mockResponse = new MockResponse('{}');

        (new WorkloadIdentityHttpClient(new MockHttpClient($mockResponse), $this->accessTokenProvider()))
            ->request('POST', 'https://api.anthropic.com/v1/messages', ['headers' => ['X-Api-Key' => 'unused']]);

        self::assertArrayNotHasKey('x-api-key', $this->sentHeaders($mockResponse));
    }

    /**
     * @throws RefusedTokenExchangeException
     * @throws TransientHttpStatusException
     * @throws UnobtainableIdentityTokenException
     */
    public function test_a_client_with_other_options_keeps_the_options_and_the_bearer_token_and_adds_the_oauth_beta(): void
    {
        $mockResponse = new MockResponse('{}');

        (new WorkloadIdentityHttpClient(new MockHttpClient($mockResponse), $this->accessTokenProvider()))
            ->withOptions(['headers' => ['anthropic-beta' => 'files-api']])
            ->request('GET', 'https://api.anthropic.com/v1/models', ['headers' => ['x-api-key' => 'unused']]);

        $headers = array_intersect_key($this->sentHeaders($mockResponse), ['anthropic-beta' => true, 'authorization' => true, 'x-api-key' => true]);
        ksort($headers);

        self::assertSame(['anthropic-beta' => ['anthropic-beta: files-api,oauth-2025-04-20'], 'authorization' => ['authorization: Bearer sk-ant-oat01-federated']], $headers);
    }

    /**
     * @throws RefusedTokenExchangeException
     * @throws TransientHttpStatusException
     * @throws UnobtainableIdentityTokenException
     */
    public function test_it_streams_the_responses_of_its_requests(): void
    {
        $workloadIdentityHttpClient = new WorkloadIdentityHttpClient(new MockHttpClient(new MockResponse(['event: ping', "\n"])), $this->accessTokenProvider());
        $response = $workloadIdentityHttpClient->request('POST', 'https://api.anthropic.com/v1/messages');

        $streamed = '';
        foreach ($workloadIdentityHttpClient->stream($response) as $chunk) {
            $streamed .= $chunk->getContent();
        }

        self::assertSame("event: ping\n", $streamed);
    }

    /**
     * @throws RefusedTokenExchangeException
     * @throws TransientHttpStatusException
     * @throws UnobtainableIdentityTokenException
     */
    public function test_it_adds_the_oauth_beta_to_a_beta_header_written_as_one_line(): void
    {
        $mockResponse = new MockResponse('{}');

        (new WorkloadIdentityHttpClient(new MockHttpClient($mockResponse), $this->accessTokenProvider()))
            ->request('POST', 'https://api.anthropic.com/v1/messages', ['headers' => ['anthropic-beta: files-api']]);

        self::assertSame(['anthropic-beta: files-api,oauth-2025-04-20'], $this->sentHeaders($mockResponse)['anthropic-beta'] ?? null);
    }

    /**
     * @throws RefusedTokenExchangeException
     * @throws TransientHttpStatusException
     * @throws UnobtainableIdentityTokenException
     */
    public function test_it_keeps_another_header_written_as_one_line(): void
    {
        $mockResponse = new MockResponse('{}');

        (new WorkloadIdentityHttpClient(new MockHttpClient($mockResponse), $this->accessTokenProvider()))
            ->request('POST', 'https://api.anthropic.com/v1/messages', ['headers' => ['anthropic-version: 2023-06-01']]);

        self::assertSame(['anthropic-version: 2023-06-01'], $this->sentHeaders($mockResponse)['anthropic-version'] ?? null);
    }

    /**
     * @throws RefusedTokenExchangeException
     * @throws TransientHttpStatusException
     * @throws UnobtainableIdentityTokenException
     */
    public function test_a_client_given_options_without_headers_keeps_the_beta_header_of_the_options_before(): void
    {
        $mockResponse = new MockResponse('{}');

        (new WorkloadIdentityHttpClient(new MockHttpClient($mockResponse), $this->accessTokenProvider()))
            ->withOptions(['headers' => ['Anthropic-Beta' => 'files-api']])
            ->withOptions(['timeout' => 5])
            ->request('POST', 'https://api.anthropic.com/v1/messages');

        self::assertSame(['anthropic-beta: files-api,oauth-2025-04-20'], $this->sentHeaders($mockResponse)['anthropic-beta'] ?? null);
    }

    /**
     * @throws RefusedTokenExchangeException
     * @throws TransientHttpStatusException
     * @throws UnobtainableIdentityTokenException
     */
    public function test_it_passes_the_other_request_options_through(): void
    {
        $mockResponse = new MockResponse('{}');

        (new WorkloadIdentityHttpClient(new MockHttpClient($mockResponse), $this->accessTokenProvider()))
            ->request('POST', 'https://api.anthropic.com/v1/messages', ['body' => '{"model":"claude-opus-5-5"}', 'headers' => ['x-api-key' => 'unused']]);

        self::assertSame('{"model":"claude-opus-5-5"}', $mockResponse->getRequestOptions()['body'] ?? null);
    }

    /**
     * @return array<mixed>
     */
    private function sentHeaders(MockResponse $mockResponse): array
    {
        $normalizedHeaders = $mockResponse->getRequestOptions()['normalized_headers'];
        self::assertIsArray($normalizedHeaders);

        return $normalizedHeaders;
    }

    private function accessTokenProvider(): AccessTokenProviderInterface
    {
        $accessTokenProvider = self::createStub(AccessTokenProviderInterface::class);
        $accessTokenProvider->method('accessToken')->willReturn('sk-ant-oat01-federated');

        return $accessTokenProvider;
    }
}
