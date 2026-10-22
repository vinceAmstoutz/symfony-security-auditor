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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\SymfonyAiLLMClient;

/**
 * Adds a configuration notice when `audit.escalation` runs its cheap first
 * pass on the bundled client although the application wired its own client
 * in place of the attacker or reviewer one: the cheap pass has a client of
 * its own, which still sends the code to the symfony/ai platform. It runs
 * before the bundle's usage-booking decorators, while each id still names the
 * client the application wired.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class CheapAttackerClientNoticePass implements CompilerPassInterface
{
    private const string CONFIG_NOTICES = 'symfony_security_auditor.config_notices';

    private const string CHEAP_ATTACKER = 'security_auditor.cheap_attacker';

    private const string CHEAP_ATTACKER_CLIENT = 'security_auditor.cheap_attacker_client';

    private const array REPLACEABLE_CLIENTS = ['security_auditor.attacker_client', 'security_auditor.reviewer_client'];

    private const string NOTICE = 'audit.escalation is enabled and an application client replaces %s but not security_auditor.cheap_attacker_client: the cheap first pass still runs on the bundled client, which sends the code to the symfony/ai platform with audit.escalation.cheap_model. Replace security_auditor.cheap_attacker_client as well (see docs/extending.md), or set audit.escalation.enabled: false.';

    #[Override]
    public function process(ContainerBuilder $container): void
    {
        if (!$container->hasDefinition(self::CHEAP_ATTACKER) || !$this->isBundled($container, self::CHEAP_ATTACKER_CLIENT)) {
            return;
        }

        $replacedClients = array_filter(
            self::REPLACEABLE_CLIENTS,
            fn (string $clientId): bool => !$this->isBundled($container, $clientId),
        );
        if ([] === $replacedClients) {
            return;
        }

        $notices = $container->getParameter(self::CONFIG_NOTICES);
        $container->setParameter(self::CONFIG_NOTICES, [
            ...(\is_array($notices) ? $notices : []),
            \sprintf(self::NOTICE, implode(' and ', $replacedClients)),
        ]);
    }

    private function isBundled(ContainerBuilder $containerBuilder, string $clientId): bool
    {
        return SymfonyAiLLMClient::class === $containerBuilder->findDefinition($clientId)->getClass();
    }
}
