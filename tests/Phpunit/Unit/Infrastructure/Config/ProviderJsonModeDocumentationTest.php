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
use Symfony\Component\Config\Definition\BaseNode;
use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\AuditConfigurationDefinition;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformOptionsFactory;

final class ProviderJsonModeDocumentationTest extends TestCase
{
    /**
     * @throws JsonException
     */
    public function test_the_json_schema_describes_provider_json_mode_as_forwarded_to_anthropic_models_only(): void
    {
        $schema = json_decode((string) file_get_contents(__DIR__.'/../../../../../resources/schema.json'), true, 512, \JSON_THROW_ON_ERROR);
        self::assertIsArray($schema);
        $properties = $schema['properties'];
        self::assertIsArray($properties);
        $bundle = $properties['symfony_security_auditor'];
        self::assertIsArray($bundle);
        $bundleProperties = $bundle['properties'];
        self::assertIsArray($bundleProperties);
        $providerJsonMode = $bundleProperties['provider_json_mode'];
        self::assertIsArray($providerJsonMode);
        $description = $providerJsonMode['description'];

        self::assertIsString($description);
        $this->assertAnthropicDialectOnly($description);
    }

    public function test_the_configuration_reference_describes_provider_json_mode_as_forwarded_to_anthropic_models_only(): void
    {
        $treeBuilder = new TreeBuilder('symfony_security_auditor');
        (new AuditConfigurationDefinition())->defineChildren($treeBuilder->getRootNode()->children());
        $tree = $treeBuilder->buildTree();
        self::assertInstanceOf(ArrayNode::class, $tree);
        $node = $tree->getChildren()['provider_json_mode'];
        self::assertInstanceOf(BaseNode::class, $node);

        $this->assertAnthropicDialectOnly((string) $node->getInfo());
    }

    #[DataProvider('modelsOtherThanAnthropic')]
    public function test_provider_json_mode_sends_no_response_format_to_a_model_other_than_anthropic(string $model): void
    {
        $options = (new PlatformOptionsFactory($model, null, true, 4096))->baseOptions();

        self::assertSame([], $options);
    }

    public function test_provider_json_mode_sends_a_json_object_response_format_to_an_anthropic_model(): void
    {
        $options = (new PlatformOptionsFactory('claude-opus-4-8', null, true, null))->baseOptions();

        self::assertSame(['response_format' => ['type' => 'json_object']], $options);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function modelsOtherThanAnthropic(): iterable
    {
        yield 'OpenAI' => ['gpt-5.6'];
        yield 'Mistral' => ['mistral-large-latest'];
        yield 'Ollama' => ['llama3.3'];
    }

    private function assertAnthropicDialectOnly(string $description): void
    {
        self::assertStringContainsString('Claude', $description);
        self::assertStringNotContainsString('OpenAI', $description);
        self::assertStringNotContainsString('Mistral', $description);
        self::assertStringNotContainsString('Ollama', $description);
    }
}
