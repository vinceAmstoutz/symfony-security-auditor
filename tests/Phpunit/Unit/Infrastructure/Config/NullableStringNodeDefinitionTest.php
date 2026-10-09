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

use Override;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\ArrayNode;
use Symfony\Component\Config\Definition\BaseNode;
use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\Config\Definition\Exception\InvalidTypeException;
use Symfony\Component\Config\Definition\NodeInterface;
use Symfony\Component\Config\Definition\Processor;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\NullableStringNodeDefinition;

final class NullableStringNodeDefinitionTest extends TestCase
{
    private const string PLACEHOLDER = 'env_0123456789abcdef_SSA_VALUE_fedcba9876543210';

    #[Override]
    protected function tearDown(): void
    {
        BaseNode::resetPlaceholders();
    }

    public function test_it_keeps_an_explicit_null_as_null(): void
    {
        self::assertNull($this->process([['name' => null]])['name']);
    }

    public function test_an_explicit_null_resets_a_value_set_by_an_earlier_configuration(): void
    {
        self::assertNull($this->process([['name' => 'first'], ['name' => null]])['name']);
    }

    public function test_it_reads_a_string_as_written(): void
    {
        self::assertSame('claude-haiku-4-5', $this->process([['name' => 'claude-haiku-4-5']])['name']);
    }

    public function test_it_reads_a_blank_string_as_written_when_blank_is_allowed(): void
    {
        self::assertSame('', $this->process([['name' => '']])['name']);
    }

    #[DataProvider('valuesThatAreNotText')]
    public function test_it_refuses_a_value_that_is_not_a_string_naming_the_key_and_its_type(mixed $value, string $type): void
    {
        $this->expectException(InvalidTypeException::class);
        $this->expectExceptionMessage(\sprintf('Invalid type for path "root.name". Expected "string", but got "%s".', $type));

        $this->process([['name' => $value]]);
    }

    /**
     * @return iterable<string, array{mixed, string}>
     */
    public static function valuesThatAreNotText(): iterable
    {
        yield 'an integer' => [2024, 'int'];
        yield 'zero' => [0, 'int'];
        yield 'a float' => [1.5, 'float'];
        yield 'true' => [true, 'bool'];
        yield 'false' => [false, 'bool'];
    }

    public function test_it_refuses_a_blank_string_when_it_cannot_be_empty(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('The path "root.name" cannot contain an empty value, but got "".');

        $this->process([['name' => '']], cannotBeEmpty: true);
    }

    public function test_it_accepts_null_when_it_cannot_be_empty(): void
    {
        $processed = $this->process([['name' => null]], cannotBeEmpty: true);

        self::assertNull($processed['name']);
    }

    public function test_it_accepts_a_string_when_it_cannot_be_empty(): void
    {
        $processed = $this->process([['name' => 'gpt-4o']], cannotBeEmpty: true);

        self::assertSame('gpt-4o', $processed['name']);
    }

    public function test_a_placeholder_that_stands_for_an_empty_string_is_not_a_blank_value(): void
    {
        BaseNode::setPlaceholder(self::PLACEHOLDER, ['string' => '']);

        self::assertSame(self::PLACEHOLDER, $this->node(cannotBeEmpty: true)->finalize(self::PLACEHOLDER));
    }

    public function test_a_placeholder_that_stands_for_a_number_is_refused(): void
    {
        BaseNode::setPlaceholder(self::PLACEHOLDER, ['int' => 0]);

        $this->expectException(InvalidTypeException::class);
        $this->expectExceptionMessage('Invalid type for path "root.name". Expected "string", but got "int".');

        $this->node(cannotBeEmpty: false)->finalize(self::PLACEHOLDER);
    }

    /**
     * @param list<array<array-key, mixed>> $configs
     *
     * @return array<array-key, mixed>
     */
    private function process(array $configs, bool $cannotBeEmpty = false): array
    {
        return (new Processor())->process($this->tree($cannotBeEmpty), $configs);
    }

    private function node(bool $cannotBeEmpty): NodeInterface
    {
        $tree = $this->tree($cannotBeEmpty);
        self::assertInstanceOf(ArrayNode::class, $tree);

        return $tree->getChildren()['name'];
    }

    private function tree(bool $cannotBeEmpty): NodeInterface
    {
        $nullableStringNodeDefinition = (new NullableStringNodeDefinition('name'))->defaultNull();

        if ($cannotBeEmpty) {
            $nullableStringNodeDefinition->cannotBeEmpty();
        }

        $treeBuilder = new TreeBuilder('root');
        $treeBuilder->getRootNode()->children()->append($nullableStringNodeDefinition)->end();

        return $treeBuilder->buildTree();
    }
}
