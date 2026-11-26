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
use SensitiveParameter;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\UnobtainableIdentityTokenException;

/**
 * Asks the GitHub Actions runner for a fresh OIDC identity token meant for
 * the Anthropic API, as a job with the `id-token: write` permission can.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class GithubActionsIdentityToken implements IdentityTokenSourceInterface
{
    private const string ANTHROPIC_AUDIENCE = 'https://api.anthropic.com';

    public function __construct(
        private HttpClientInterface $httpClient,
        private string $requestUrl,
        #[SensitiveParameter]
        private string $requestToken,
    ) {}

    /**
     * @throws UnobtainableIdentityTokenException when the runner refuses the request or answers without a token
     */
    #[Override]
    public function identityToken(): string
    {
        $response = $this->httpClient->request('GET', $this->requestUrl, [
            'query' => ['audience' => self::ANTHROPIC_AUDIENCE],
            'auth_bearer' => $this->requestToken,
        ]);
        $identityToken = DecodedAnswer::of($response)['value'] ?? null;
        if (200 !== $response->getStatusCode() || !\is_string($identityToken)) {
            throw UnobtainableIdentityTokenException::fromGithubActions($response->getStatusCode());
        }

        return $identityToken;
    }
}
