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

use Symfony\Component\Console\Command\Command;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditCommand;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\Exception\UnresolvableAuditCommandException;

/**
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class StandaloneConsoleCommandFactory
{
    /**
     * @throws UnresolvableAuditCommandException
     */
    public function create(ContainerBuilder $containerBuilder): Command
    {
        $auditCommand = $containerBuilder->get(AuditCommand::class);
        if (!$auditCommand instanceof AuditCommand) {
            throw UnresolvableAuditCommandException::fromContainer(AuditCommand::class);
        }

        return new Command(null, $auditCommand);
    }
}
