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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Config;

use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Exception\InvalidArgumentException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\PlatformServiceId;

/**
 * `PlatformServiceId` restates the id rule `ContainerBuilder::setDefinition()`
 * enforces. Asserting that restatement against hard-coded booleans would keep
 * passing if the framework tightened the rule, and `init` would go back to
 * writing a config whose next run dies on `Invalid service id`. The real
 * container is asked instead, the way `PlatformShapeKnowledgeTest` asks the
 * bundle about platform shapes.
 */
final class PlatformServiceIdKnowledgeTest extends TestCase
{
    private const string SERVICE_ID_PREFIX = 'ai.platform.generic.';

    public function test_it_accepts_exactly_the_instance_names_the_container_does(): void
    {
        $ours = [];
        $theirs = [];

        foreach ($this->instanceNames() as $instance) {
            $ours[$instance] = PlatformServiceId::accepts($instance);
            $theirs[$instance] = $this->containerAcceptsAnIdEndingIn($instance);
        }

        self::assertSame($theirs, $ours);
    }

    /**
     * @return list<string>
     */
    private function instanceNames(): array
    {
        return [
            'my_gateway',
            'eu.west',
            'MyGateway',
            '42',
            "o'brien",
            'a"b',
            "a\nb",
            "a\rb",
            "a\0b",
            'gw\\',
            'gw\\eu',
            '%gw%',
            'gw eu',
        ];
    }

    private function containerAcceptsAnIdEndingIn(string $instance): bool
    {
        try {
            (new ContainerBuilder())->setDefinition(self::SERVICE_ID_PREFIX.$instance, new Definition(Definition::class));
        } catch (InvalidArgumentException) {
            return false;
        }

        return true;
    }
}
