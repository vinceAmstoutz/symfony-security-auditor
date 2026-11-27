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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\UnobtainableIdentityTokenException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\WorkloadIdentity\GithubActionsIdentityToken;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Fixture\ExpectsExceptionMessageTrait;

final class GithubActionsIdentityTokenTest extends TestCase
{
    use ExpectsExceptionMessageTrait;

    /**
     * @throws UnobtainableIdentityTokenException
     */
    public function test_it_asks_github_actions_for_an_identity_token_meant_for_anthropic(): void
    {
        $mockResponse = new MockResponse('{"count":1,"value":"github-oidc-jwt"}');

        $identityToken = (new GithubActionsIdentityToken(new MockHttpClient($mockResponse), 'https://pipelines.actions.githubusercontent.com/abc/idtoken?api-version=2.0', 'request-token'))->identityToken();

        $normalizedHeaders = $mockResponse->getRequestOptions()['normalized_headers'];
        self::assertIsArray($normalizedHeaders);
        self::assertSame(
            ['github-oidc-jwt', 'GET', 'https://pipelines.actions.githubusercontent.com/abc/idtoken?api-version=2.0&audience=https://api.anthropic.com', ['Authorization: Bearer request-token']],
            [$identityToken, $mockResponse->getRequestMethod(), $mockResponse->getRequestUrl(), $normalizedHeaders['authorization'] ?? null],
        );
    }

    /**
     * @throws UnobtainableIdentityTokenException
     */
    public function test_a_refused_request_names_the_permission_the_job_needs(): void
    {
        $githubActionsIdentityToken = new GithubActionsIdentityToken(new MockHttpClient(new MockResponse('{"message":"Forbidden"}', ['http_code' => 403])), 'https://pipelines.actions.githubusercontent.com/abc/idtoken', 'request-token');

        $this->expectException(UnobtainableIdentityTokenException::class);
        $this->expectExceptionMessageContaining('GitHub Actions gave no identity token (HTTP 403): give the job the "id-token: write" permission.');

        $githubActionsIdentityToken->identityToken();
    }

    /**
     * @throws UnobtainableIdentityTokenException
     */
    public function test_an_answer_without_a_token_gives_no_identity_token(): void
    {
        $githubActionsIdentityToken = new GithubActionsIdentityToken(new MockHttpClient(new MockResponse('{"count":0}')), 'https://pipelines.actions.githubusercontent.com/abc/idtoken', 'request-token');

        $this->expectException(UnobtainableIdentityTokenException::class);
        $this->expectExceptionMessageContaining('(HTTP 200)');

        $githubActionsIdentityToken->identityToken();
    }

    /**
     * @throws UnobtainableIdentityTokenException
     */
    public function test_an_answer_that_is_not_json_gives_no_identity_token(): void
    {
        $githubActionsIdentityToken = new GithubActionsIdentityToken(new MockHttpClient(new MockResponse('<html><body>Bad gateway</body></html>', ['http_code' => 502])), 'https://pipelines.actions.githubusercontent.com/abc/idtoken', 'request-token');

        $this->expectException(UnobtainableIdentityTokenException::class);
        $this->expectExceptionMessageContaining('(HTTP 502)');

        $githubActionsIdentityToken->identityToken();
    }
}
