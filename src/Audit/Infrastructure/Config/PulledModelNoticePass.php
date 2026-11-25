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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config;

use Override;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Parameter;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Ollama\OllamaPulledModelList;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Ollama\PulledModelNotice;

/**
 * Registers the notice naming the configured models the Ollama server has not
 * pulled, when the audit runs on the `ollama` platform of `symfony/ai`, with
 * the endpoint that platform is configured with.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class PulledModelNoticePass implements CompilerPassInterface
{
    public const string SERVICE = 'security_auditor.pulled_model_notice';

    public const string PLATFORM_SERVICE_PARAMETER = 'symfony_security_auditor.audit_platform_service';

    private const string OLLAMA = 'ai.platform.ollama';

    private const string MODELS_PARAMETER = 'symfony_security_auditor.audit.models_requiring_pricing';

    private const array HTTP_CLIENT_OPTIONS = ['timeout' => 3];

    #[Override]
    public function process(ContainerBuilder $container): void
    {
        if (self::OLLAMA !== $this->auditPlatformService($container) || !$container->hasDefinition(self::OLLAMA)) {
            return;
        }

        $httpClient = (new Definition(HttpClientInterface::class))->setFactory([HttpClient::class, 'create'])->setArguments([self::HTTP_CLIENT_OPTIONS]);
        $container->register(self::SERVICE, PulledModelNotice::class)->setArguments([
            new Definition(OllamaPulledModelList::class, [$httpClient]),
            $container->getDefinition(self::OLLAMA)->getArguments()[0] ?? null,
            new Parameter(self::MODELS_PARAMETER),
        ]);
    }

    private function auditPlatformService(ContainerBuilder $containerBuilder): ?string
    {
        $serviceId = $containerBuilder->hasParameter(self::PLATFORM_SERVICE_PARAMETER) ? $containerBuilder->getParameter(self::PLATFORM_SERVICE_PARAMETER) : null;
        if (!\is_string($serviceId)) {
            return null;
        }

        return $containerBuilder->hasAlias($serviceId) ? (string) $containerBuilder->getAlias($serviceId) : $serviceId;
    }
}
