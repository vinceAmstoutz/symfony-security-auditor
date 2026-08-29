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

use Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\Config\Definition\Processor;

/**
 * Applies the bundle's config tree to a raw configuration array outside the
 * bundle, so a non-bundle host gets the same defaults and validation the
 * Symfony extension would have applied.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class AuditConfigurationProcessor
{
    public const string ROOT_NODE = 'symfony_security_auditor';

    /**
     * @param array<array-key, mixed> $auditConfig
     *
     * @return array<array-key, mixed>
     *
     * @throws InvalidConfigurationException
     */
    public function process(array $auditConfig): array
    {
        $arrayNodeDefinition = new ArrayNodeDefinition(self::ROOT_NODE);
        (new AuditConfigurationDefinition())->defineChildren($arrayNodeDefinition->children());

        return (new Processor())->process($arrayNodeDefinition->getNode(), [$auditConfig]);
    }
}
