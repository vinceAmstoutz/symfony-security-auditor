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

namespace VinceAmstoutz\SymfonySecurityAuditor\Standalone;

use SensitiveParameter;
use Symfony\Component\Clock\NativeClock;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\ContainerParameterSyntax;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\UnobtainableIdentityTokenException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\WorkloadIdentity\FederatedAccessTokens;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\WorkloadIdentity\GithubActionsIdentityToken;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\WorkloadIdentity\WorkloadIdentityFederation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\WorkloadIdentity\WorkloadIdentityHttpClient;

/**
 * Authenticates the `anthropic` platform through workload identity federation
 * when the environment names a federation rule and no `ANTHROPIC_API_KEY`.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class FederatedAnthropicAccess
{
    public const string API_KEY_PLACEHOLDER = WorkloadIdentityFederation::API_KEY_PLACEHOLDER;

    public const string HTTP_CLIENT_SERVICE = 'security_auditor.workload_identity_http_client';

    private const string API_KEY_VARIABLE = 'ANTHROPIC_API_KEY';

    private const string HTTP_CLIENT = 'http_client';

    private const string ANTHROPIC = 'anthropic';

    private function __construct(
        public WorkloadIdentityFederation $workloadIdentityFederation,
        private string $identityTokenRequestUrl,
        #[SensitiveParameter]
        private string $identityTokenRequestToken,
    ) {}

    /**
     * @param array<string, string> $environment
     */
    public static function fromEnvironment(array $environment): ?self
    {
        $workloadIdentityFederation = WorkloadIdentityFederation::fromEnvironment($environment);
        if (!$workloadIdentityFederation instanceof WorkloadIdentityFederation || '' !== ($environment[self::API_KEY_VARIABLE] ?? '')) {
            return null;
        }

        return new self(
            $workloadIdentityFederation,
            $environment['ACTIONS_ID_TOKEN_REQUEST_URL'] ?? '',
            $environment['ACTIONS_ID_TOKEN_REQUEST_TOKEN'] ?? '',
        );
    }

    /**
     * @param array<string, string> $environment
     *
     * @return array<string, string>
     */
    public function environmentWithPlaceholderApiKey(array $environment): array
    {
        return [...$environment, self::API_KEY_VARIABLE => self::API_KEY_PLACEHOLDER];
    }

    /**
     * Registers the federated HTTP client and hands it to the `anthropic`
     * platform of the AI configuration.
     *
     * @param array{platform: array<array-key, mixed>} $aiConfig
     *
     * @return array{platform: array<array-key, mixed>}
     *
     * @throws UnobtainableIdentityTokenException when the run cannot request an identity token from GitHub Actions
     */
    public function configure(array $aiConfig, ContainerBuilder $containerBuilder): array
    {
        $anthropic = $aiConfig['platform'][self::ANTHROPIC] ?? null;
        if (!\is_array($anthropic)) {
            return $aiConfig;
        }

        if ('' === $this->identityTokenRequestUrl || '' === $this->identityTokenRequestToken) {
            throw UnobtainableIdentityTokenException::outsideGithubActions();
        }

        $containerBuilder->register(self::HTTP_CLIENT_SERVICE, WorkloadIdentityHttpClient::class)->setArguments([
            new Reference(self::HTTP_CLIENT),
            new Definition(FederatedAccessTokens::class, [
                new Reference(self::HTTP_CLIENT),
                new Definition(WorkloadIdentityFederation::class, array_map(
                    static fn (?string $value): ?string => null === $value ? null : ContainerParameterSyntax::escape($value),
                    [
                        $this->workloadIdentityFederation->ruleId,
                        $this->workloadIdentityFederation->organizationId,
                        $this->workloadIdentityFederation->serviceAccountId,
                        $this->workloadIdentityFederation->workspaceId,
                    ],
                )),
                new Definition(GithubActionsIdentityToken::class, [
                    new Reference(self::HTTP_CLIENT),
                    ContainerParameterSyntax::escape($this->identityTokenRequestUrl),
                    ContainerParameterSyntax::escape($this->identityTokenRequestToken),
                ]),
                new Definition(NativeClock::class),
            ]),
        ]);

        return ['platform' => [...$aiConfig['platform'], self::ANTHROPIC => [...$anthropic, self::HTTP_CLIENT => self::HTTP_CLIENT_SERVICE]]];
    }
}
