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
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\ArrayNode;
use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\EnumNode;
use Symfony\Component\Config\Definition\NodeInterface;
use Symfony\Component\Config\Definition\PrototypedArrayNode;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\AuditConfigurationDefinition;

final class ConfigurationSchemaEnumParityTest extends TestCase
{
    private const string ROOT = 'symfony_security_auditor';

    /**
     * @return iterable<string, array{array<mixed>, mixed}>
     *
     * @throws JsonException
     */
    public static function choiceSettings(): iterable
    {
        $treeBuilder = new TreeBuilder(self::ROOT);
        (new AuditConfigurationDefinition())->defineChildren($treeBuilder->getRootNode()->children());

        yield from self::choicesUnder($treeBuilder->buildTree(), self::bundleSchema(), self::ROOT);
    }

    /**
     * @param array<mixed> $acceptedValues
     */
    #[DataProvider('choiceSettings')]
    public function test_the_json_schema_offers_exactly_the_choices_the_configuration_tree_accepts(array $acceptedValues, mixed $schemaChoices): void
    {
        self::assertSame($acceptedValues, $schemaChoices);
    }

    public function test_the_configuration_tree_has_a_choice_setting_for_every_vulnerability_type_list_and_the_skill_file_type(): void
    {
        $vulnerabilityTypes = array_map(static fn (VulnerabilityType $vulnerabilityType): string => $vulnerabilityType->value, VulnerabilityType::cases());
        $projectFileTypes = array_map(static fn (ProjectFileType $projectFileType): string => $projectFileType->value, ProjectFileType::cases());

        $choiceSettings = iterator_to_array(self::choiceSettings());

        self::assertSame([$vulnerabilityTypes, $vulnerabilityTypes], $choiceSettings['symfony_security_auditor.audit.excluded_types.*']);
        self::assertSame([$vulnerabilityTypes, $vulnerabilityTypes], $choiceSettings['symfony_security_auditor.audit.included_types.*']);
        self::assertSame([$projectFileTypes, $projectFileTypes], $choiceSettings['symfony_security_auditor.audit.custom_skills.*.file_type']);
    }

    /**
     * @return iterable<string, array{array<mixed>, mixed}>
     */
    private static function choicesUnder(NodeInterface $node, mixed $schema, string $path): iterable
    {
        if ($node instanceof EnumNode) {
            yield $path => [$node->getValues(), self::schemaKeyword($schema, 'enum')];

            return;
        }

        if ($node instanceof PrototypedArrayNode) {
            yield from self::choicesUnder($node->getPrototype(), self::schemaKeyword($schema, 'items') ?? self::schemaKeyword($schema, 'additionalProperties'), \sprintf('%s.*', $path));

            return;
        }

        if (!$node instanceof ArrayNode) {
            return;
        }

        foreach ($node->getChildren() as $name => $child) {
            yield from self::choicesUnder($child, self::schemaKeyword(self::schemaKeyword($schema, 'properties'), $name), \sprintf('%s.%s', $path, $name));
        }
    }

    private static function schemaKeyword(mixed $schema, string $keyword): mixed
    {
        return \is_array($schema) ? $schema[$keyword] ?? null : null;
    }

    /**
     * @throws JsonException
     */
    private static function bundleSchema(): mixed
    {
        $schema = json_decode((string) file_get_contents(__DIR__.'/../../../../../resources/schema.json'), true, 512, \JSON_THROW_ON_ERROR);

        return self::schemaKeyword(self::schemaKeyword($schema, 'properties'), self::ROOT);
    }
}
