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

use DateTimeImmutable;
use Override;
use Psr\Clock\ClockInterface;
use Symfony\Contracts\HttpClient\Exception\DecodingExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Symfony\Contracts\HttpClient\ResponseInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\RefusedTokenExchangeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\TransientHttpStatusException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\UnobtainableIdentityTokenException;

/**
 * Exchanges the workload's identity token for an Anthropic access token
 * through workload identity federation. Reuses that token until a minute
 * before it expires.
 *
 * Not readonly: keeps the access token across calls (stateful collaborator,
 * see .claude/rules/php-classes.md).
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final class FederatedAccessTokens implements AccessTokenProviderInterface
{
    private const string TOKEN_PATH = '/v1/oauth/token';

    private const int RENEWAL_MARGIN_SECONDS = 60;

    private const array RETRIED_CLIENT_ERROR_STATUSES = [408, 425, 429];

    private const int FIRST_SERVER_ERROR_STATUS = 500;

    private const string NO_REASON = 'no reason given';

    private string $accessToken = '';

    private DateTimeImmutable $renewAt;

    public function __construct(
        private readonly HttpClientInterface $httpClient,
        private readonly WorkloadIdentityFederation $workloadIdentityFederation,
        private readonly IdentityTokenSourceInterface $identityTokenSource,
        private readonly ClockInterface $clock,
        private readonly string $baseUrl = 'https://api.anthropic.com',
    ) {
        $this->renewAt = new DateTimeImmutable('@0');
    }

    /**
     * @throws RefusedTokenExchangeException      when the exchange is refused, or answers without an access token
     * @throws TransientHttpStatusException       when the token endpoint answers with a status worth retrying
     * @throws UnobtainableIdentityTokenException when the workload gets no identity token
     */
    #[Override]
    public function accessToken(): string
    {
        if ($this->clock->now() < $this->renewAt) {
            return $this->accessToken;
        }

        $response = $this->httpClient->request('POST', \sprintf('%s%s', $this->baseUrl, self::TOKEN_PATH), [
            'json' => $this->workloadIdentityFederation->exchangeRequest($this->identityTokenSource->identityToken()),
        ]);
        $answer = $this->answerOf($response);
        $accessToken = $answer['access_token'] ?? null;
        if (200 !== $response->getStatusCode() || !\is_string($accessToken)) {
            throw $this->refusal($response->getStatusCode(), $this->reasonIn($answer));
        }

        $this->accessToken = $accessToken;
        $this->renewAt = $this->renewalTime($answer['expires_in'] ?? null);

        return $this->accessToken;
    }

    private function renewalTime(mixed $lifetime): DateTimeImmutable
    {
        $now = $this->clock->now();

        return \is_int($lifetime) ? $now->modify(\sprintf('+%d seconds', $lifetime - self::RENEWAL_MARGIN_SECONDS)) : $now;
    }

    /**
     * @param array<mixed> $answer
     */
    private function reasonIn(array $answer): string
    {
        $error = $answer['error'] ?? null;
        $reason = $answer['error_description'] ?? (\is_array($error) ? $error['message'] ?? null : null);

        return \is_string($reason) ? $reason : self::NO_REASON;
    }

    /**
     * @return array<mixed>
     */
    private function answerOf(ResponseInterface $response): array
    {
        try {
            return $response->toArray(false);
        } catch (DecodingExceptionInterface) {
            return [];
        }
    }

    private function refusal(int $status, string $reason): RefusedTokenExchangeException|TransientHttpStatusException
    {
        $refusedTokenExchangeException = RefusedTokenExchangeException::forStatus($status, $reason);

        return \in_array($status, self::RETRIED_CLIENT_ERROR_STATUSES, true) || $status >= self::FIRST_SERVER_ERROR_STATUS
            ? TransientHttpStatusException::from($refusedTokenExchangeException, $status)
            : $refusedTokenExchangeException;
    }
}
