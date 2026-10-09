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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Config;

use JsonException;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\ArrayNode;
use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\EnumNode;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Configuration\ToolsScope;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\AuditConfigurationDefinition;

final class ToolsScopeDocumentationTest extends TestCase
{
    public function test_the_configuration_tree_offers_every_scope_and_defaults_to_the_audited_files(): void
    {
        $treeBuilder = new TreeBuilder('symfony_security_auditor');
        (new AuditConfigurationDefinition())->defineChildren($treeBuilder->getRootNode()->children());
        $node = $treeBuilder->buildTree();
        self::assertInstanceOf(ArrayNode::class, $node);
        $audit = $node->getChildren()['audit'];
        self::assertInstanceOf(ArrayNode::class, $audit);
        $toolsScope = $audit->getChildren()['tools_scope'];
        self::assertInstanceOf(EnumNode::class, $toolsScope);

        self::assertSame($this->scopeValues(), $toolsScope->getValues());
        self::assertSame(ToolsScope::Audited->value, $toolsScope->getDefaultValue());
    }

    /**
     * @throws JsonException
     */
    public function test_the_json_schema_offers_every_scope(): void
    {
        $schema = json_decode((string) file_get_contents(__DIR__.'/../../../../../resources/schema.json'), true, 512, \JSON_THROW_ON_ERROR);
        self::assertIsArray($schema);
        $properties = $schema['properties'];
        self::assertIsArray($properties);
        $bundle = $properties['symfony_security_auditor'];
        self::assertIsArray($bundle);
        $bundleProperties = $bundle['properties'];
        self::assertIsArray($bundleProperties);
        $audit = $bundleProperties['audit'];
        self::assertIsArray($audit);
        $auditProperties = $audit['properties'];
        self::assertIsArray($auditProperties);
        $toolsScope = $auditProperties['tools_scope'];
        self::assertIsArray($toolsScope);

        self::assertSame($this->scopeValues(), $toolsScope['enum']);
    }

    /**
     * @return list<string>
     */
    private function scopeValues(): array
    {
        return array_map(static fn (ToolsScope $toolsScope): string => $toolsScope->value, ToolsScope::cases());
    }
}
