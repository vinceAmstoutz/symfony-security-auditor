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

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\RefusedTokenExchangeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\TransientHttpStatusException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\UnobtainableIdentityTokenException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\WorkloadIdentity\FederatedAccessTokens;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\WorkloadIdentity\IdentityTokenSourceInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\WorkloadIdentity\WorkloadIdentityFederation;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Fixture\ExpectsExceptionMessageTrait;

final class FederatedAccessTokensTest extends TestCase
{
    use ExpectsExceptionMessageTrait;

    /**
     * @throws RefusedTokenExchangeException
     * @throws TransientHttpStatusException
     * @throws UnobtainableIdentityTokenException
     */
    public function test_it_exchanges_the_identity_token_for_an_access_token(): void
    {
        $federatedAccessTokens = new FederatedAccessTokens(
            new MockHttpClient(new MockResponse('{"access_token":"sk-ant-oat01-first","expires_in":599,"token_type":"Bearer"}')),
            new WorkloadIdentityFederation('fdrl_rule', 'org-uuid'),
            $this->identityTokenSource(),
            new MockClock(),
        );

        self::assertSame('sk-ant-oat01-first', $federatedAccessTokens->accessToken());
    }

    /**
     * @throws RefusedTokenExchangeException
     * @throws TransientHttpStatusException
     * @throws UnobtainableIdentityTokenException
     */
    public function test_it_posts_the_identity_token_with_the_federation_rule_to_the_token_endpoint(): void
    {
        $mockResponse = new MockResponse('{"access_token":"sk-ant-oat01-first","expires_in":599}');

        (new FederatedAccessTokens(
            new MockHttpClient($mockResponse),
            new WorkloadIdentityFederation('fdrl_rule', 'org-uuid', 'svac_account', 'wrkspc_space'),
            $this->identityTokenSource(),
            new MockClock(),
        ))->accessToken();

        self::assertSame(
            ['POST', 'https://api.anthropic.com/v1/oauth/token', [
                'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
                'assertion' => 'github-oidc-jwt',
                'federation_rule_id' => 'fdrl_rule',
                'organization_id' => 'org-uuid',
                'service_account_id' => 'svac_account',
                'workspace_id' => 'wrkspc_space',
            ]],
            [$mockResponse->getRequestMethod(), $mockResponse->getRequestUrl(), $this->sentBody($mockResponse)],
        );
    }

    /**
     * @throws RefusedTokenExchangeException
     * @throws TransientHttpStatusException
     * @throws UnobtainableIdentityTokenException
     */
    public function test_it_leaves_out_the_service_account_and_workspace_the_rule_does_not_name(): void
    {
        $mockResponse = new MockResponse('{"access_token":"sk-ant-oat01-first","expires_in":599}');

        (new FederatedAccessTokens(new MockHttpClient($mockResponse), new WorkloadIdentityFederation('fdrl_rule', 'org-uuid'), $this->identityTokenSource(), new MockClock()))->accessToken();

        self::assertSame(
            ['grant_type', 'assertion', 'federation_rule_id', 'organization_id'],
            array_keys($this->sentBody($mockResponse)),
        );
    }

    /**
     * @throws RefusedTokenExchangeException
     * @throws TransientHttpStatusException
     * @throws UnobtainableIdentityTokenException
     */
    public function test_it_reuses_the_access_token_while_it_stays_valid(): void
    {
        $mockClock = new MockClock();
        $federatedAccessTokens = new FederatedAccessTokens($this->twoExchanges(), new WorkloadIdentityFederation('fdrl_rule', 'org-uuid'), $this->identityTokenSource(), $mockClock);

        $federatedAccessTokens->accessToken();

        $mockClock->sleep(538);

        self::assertSame('sk-ant-oat01-first', $federatedAccessTokens->accessToken());
    }

    /**
     * @throws RefusedTokenExchangeException
     * @throws TransientHttpStatusException
     * @throws UnobtainableIdentityTokenException
     */
    public function test_it_exchanges_a_new_access_token_a_minute_before_the_first_one_expires(): void
    {
        $mockClock = new MockClock();
        $federatedAccessTokens = new FederatedAccessTokens($this->twoExchanges(), new WorkloadIdentityFederation('fdrl_rule', 'org-uuid'), $this->identityTokenSource(), $mockClock);

        $federatedAccessTokens->accessToken();

        $mockClock->sleep(539);

        self::assertSame('sk-ant-oat01-second', $federatedAccessTokens->accessToken());
    }

    /**
     * @throws RefusedTokenExchangeException
     * @throws TransientHttpStatusException
     * @throws UnobtainableIdentityTokenException
     */
    public function test_a_refused_exchange_stops_with_the_status_and_the_reason_anthropic_gives(): void
    {
        $federatedAccessTokens = new FederatedAccessTokens(
            new MockHttpClient(new MockResponse('{"error":"invalid_grant","error_description":"The identity token does not match the rule."}', ['http_code' => 401])),
            new WorkloadIdentityFederation('fdrl_rule', 'org-uuid'),
            $this->identityTokenSource(),
            new MockClock(),
        );

        $this->expectException(RefusedTokenExchangeException::class);
        $this->expectExceptionMessageContaining('Workload identity federation refused the token exchange (HTTP 401): The identity token does not match the rule.');

        $federatedAccessTokens->accessToken();
    }

    /**
     * @throws RefusedTokenExchangeException
     * @throws TransientHttpStatusException
     * @throws UnobtainableIdentityTokenException
     */
    public function test_a_refusal_in_the_anthropic_error_format_gives_its_message(): void
    {
        $federatedAccessTokens = $this->exchangeAnswering(new MockResponse('{"type":"error","error":{"type":"permission_error","message":"The rule does not trust this subject."}}', ['http_code' => 403]));

        $this->expectException(RefusedTokenExchangeException::class);
        $this->expectExceptionMessageContaining('(HTTP 403): The rule does not trust this subject.');

        $federatedAccessTokens->accessToken();
    }

    /**
     * @throws RefusedTokenExchangeException
     * @throws TransientHttpStatusException
     * @throws UnobtainableIdentityTokenException
     */
    public function test_a_gateway_failure_is_retried_and_stops_as_a_refusal_once_the_retries_are_spent(): void
    {
        $federatedAccessTokens = $this->exchangeAnswering(new MockResponse('<html><body>Bad gateway</body></html>', ['http_code' => 502]));

        try {
            $federatedAccessTokens->accessToken();
            self::fail('The exchange should have failed.');
        } catch (TransientHttpStatusException $transientHttpStatusException) {
            self::assertSame(
                [502, RefusedTokenExchangeException::class, 'Workload identity federation refused the token exchange (HTTP 502): no reason given'],
                [$transientHttpStatusException->status, $transientHttpStatusException->statusFreeFailure::class, $transientHttpStatusException->statusFreeFailure->getMessage()],
            );
        }
    }

    /**
     * @param class-string<Throwable> $failure
     *
     * @throws RefusedTokenExchangeException
     * @throws TransientHttpStatusException
     * @throws UnobtainableIdentityTokenException
     */
    #[DataProvider('statusFailures')]
    public function test_only_a_status_worth_retrying_fails_as_retryable(int $status, string $failure): void
    {
        $federatedAccessTokens = $this->exchangeAnswering(new MockResponse('{}', ['http_code' => $status]));

        $this->expectException($failure);

        $federatedAccessTokens->accessToken();
    }

    /**
     * @return iterable<string, array{int, class-string<Throwable>}>
     */
    public static function statusFailures(): iterable
    {
        yield 'request timeout' => [408, TransientHttpStatusException::class];
        yield 'too early' => [425, TransientHttpStatusException::class];
        yield 'rate limit' => [429, TransientHttpStatusException::class];
        yield 'first server error' => [500, TransientHttpStatusException::class];
        yield 'last client error' => [499, RefusedTokenExchangeException::class];
        yield 'unauthorized' => [401, RefusedTokenExchangeException::class];
    }

    /**
     * @throws RefusedTokenExchangeException
     * @throws TransientHttpStatusException
     * @throws UnobtainableIdentityTokenException
     */
    public function test_an_answer_without_an_access_token_is_a_refusal(): void
    {
        $federatedAccessTokens = $this->exchangeAnswering(new MockResponse('{"token_type":"Bearer"}'));

        $this->expectException(RefusedTokenExchangeException::class);
        $this->expectExceptionMessageContaining('(HTTP 200): no reason given');

        $federatedAccessTokens->accessToken();
    }

    /**
     * @throws RefusedTokenExchangeException
     * @throws TransientHttpStatusException
     * @throws UnobtainableIdentityTokenException
     */
    public function test_an_access_token_without_a_lifetime_is_exchanged_again_on_the_next_call(): void
    {
        $federatedAccessTokens = new FederatedAccessTokens(
            new MockHttpClient([new MockResponse('{"access_token":"sk-ant-oat01-first"}'), new MockResponse('{"access_token":"sk-ant-oat01-second"}')]),
            new WorkloadIdentityFederation('fdrl_rule', 'org-uuid'),
            $this->identityTokenSource(),
            new MockClock(),
        );

        $federatedAccessTokens->accessToken();

        self::assertSame('sk-ant-oat01-second', $federatedAccessTokens->accessToken());
    }

    private function exchangeAnswering(MockResponse $mockResponse): FederatedAccessTokens
    {
        return new FederatedAccessTokens(new MockHttpClient($mockResponse), new WorkloadIdentityFederation('fdrl_rule', 'org-uuid'), $this->identityTokenSource(), new MockClock());
    }

    private function twoExchanges(): MockHttpClient
    {
        return new MockHttpClient([
            new MockResponse('{"access_token":"sk-ant-oat01-first","expires_in":599}'),
            new MockResponse('{"access_token":"sk-ant-oat01-second","expires_in":599}'),
        ]);
    }

    /**
     * @return array<mixed>
     */
    private function sentBody(MockResponse $mockResponse): array
    {
        $body = $mockResponse->getRequestOptions()['body'];
        self::assertIsString($body);
        $decoded = json_decode($body, true, flags: \JSON_THROW_ON_ERROR);
        self::assertIsArray($decoded);

        return $decoded;
    }

    private function identityTokenSource(): IdentityTokenSourceInterface
    {
        $identityTokenSource = self::createStub(IdentityTokenSourceInterface::class);
        $identityTokenSource->method('identityToken')->willReturn('github-oidc-jwt');

        return $identityTokenSource;
    }
}
