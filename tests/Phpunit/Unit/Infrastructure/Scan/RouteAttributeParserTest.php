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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Scan;

use Override;
use PhpParser\Node\Stmt\Class_;
use PhpParser\NodeFinder;
use PhpParser\ParserFactory;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\RouteAttributeParser;

final class RouteAttributeParserTest extends TestCase
{
    private RouteAttributeParser $routeAttributeParser;

    #[Override]
    protected function setUp(): void
    {
        $this->routeAttributeParser = new RouteAttributeParser();
    }

    public function test_it_reads_a_string_route_path(): void
    {
        self::assertSame('/hello', $this->extractFrom("#[Route('/hello')]")[0]['path']);
    }

    public function test_it_reads_the_first_string_of_a_localized_route_path_array(): void
    {
        self::assertSame('/en/hello', $this->extractFrom("#[Route(path: ['/en/hello', '/fr/bonjour'])]")[0]['path']);
    }

    public function test_it_reads_a_null_path_from_an_empty_route_path_array(): void
    {
        self::assertNull($this->extractFrom('#[Route(path: [])]')[0]['path']);
    }

    public function test_it_resolves_a_self_class_constant_route_path(): void
    {
        self::assertSame('/from-const', $this->extractFrom('#[Route(path: self::PATH)]', ['PATH' => '/from-const'])[0]['path']);
    }

    public function test_it_does_not_resolve_a_constant_from_another_class_as_a_route_path(): void
    {
        self::assertNull($this->extractFrom('#[Route(path: Other::PATH)]', ['PATH' => '/from-const'])[0]['path']);
    }

    /**
     * @param array<string, string> $classConstants
     *
     * @return list<array{present: bool, path: ?string, methods: list<string>, name: ?string}>
     */
    private function extractFrom(string $attribute, array $classConstants = []): array
    {
        $parserFactory = new ParserFactory();
        $parser = $parserFactory->createForNewestSupportedVersion();
        $ast = $parser->parse("<?php\n{$attribute}\nfinal class C {}") ?? [];

        $class = (new NodeFinder())->findFirstInstanceOf($ast, Class_::class);
        self::assertInstanceOf(Class_::class, $class);

        return $this->routeAttributeParser->extract($class->attrGroups, $classConstants);
    }
}
