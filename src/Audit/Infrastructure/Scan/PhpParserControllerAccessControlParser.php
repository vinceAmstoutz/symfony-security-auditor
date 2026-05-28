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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan;

use PhpParser\Node\AttributeGroup;
use PhpParser\Node\Expr\Array_;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Identifier;
use PhpParser\Node\Scalar\String_;
use PhpParser\Node\Stmt\Class_;
use PhpParser\Node\Stmt\ClassMethod;
use PhpParser\NodeFinder;
use PhpParser\ParserFactory;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RouteAccessControl;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ControllerAccessControlParserInterface;

/**
 * @internal not part of the BC promise — see docs/versioning.md
 *
 * Walks a controller's AST to extract one RouteAccessControl per public action
 * method. Recognises `#[Route(path:, methods:)]` on methods, `#[IsGranted(...)]`
 * on both class and method level (matched by short name to survive aliased
 * imports), and `denyAccessUnlessGranted()` calls in method bodies. Returns
 * [] for any non-controller file or any parse error — the mapping stage must
 * never abort because of a single broken file.
 */
final readonly class PhpParserControllerAccessControlParser implements ControllerAccessControlParserInterface
{
    public function parse(ProjectFile $projectFile): array
    {
        if (ProjectFileType::CONTROLLER !== $projectFile->fileType()) {
            return [];
        }

        try {
            $parserFactory = new ParserFactory();
            $parser = $parserFactory->createForNewestSupportedVersion();
            $ast = $parser->parse($projectFile->content());

            if (null === $ast) {
                return [];
            }
        } catch (Throwable) {
            return [];
        }

        $nodeFinder = new NodeFinder();
        $classes = $nodeFinder->findInstanceOf($ast, Class_::class);

        $entries = [];
        foreach ($classes as $class) {
            $classHasIsGranted = $this->hasIsGrantedAttribute($class->attrGroups);

            foreach ($class->getMethods() as $methodNode) {
                if (!$methodNode->isPublic()) {
                    continue;
                }

                $entries[] = $this->buildEntry($projectFile->relativePath(), $methodNode, $classHasIsGranted, $nodeFinder);
            }
        }

        return $entries;
    }

    private function buildEntry(string $filePath, ClassMethod $classMethod, bool $classHasIsGranted, NodeFinder $nodeFinder): RouteAccessControl
    {
        $routeData = $this->extractRouteAttribute($classMethod->attrGroups);
        $methodLevelIsGranted = $this->extractIsGrantedValues($classMethod->attrGroups);
        $methodHasDenyAccess = $this->methodInvokesDenyAccess($classMethod, $nodeFinder);

        return new RouteAccessControl(
            filePath: $filePath,
            methodName: $classMethod->name->toString(),
            routePath: $routeData['path'],
            routeMethods: $routeData['methods'],
            hasRouteAttribute: $routeData['present'],
            methodLevelIsGranted: $methodLevelIsGranted,
            methodHasDenyAccess: $methodHasDenyAccess,
            classHasIsGranted: $classHasIsGranted,
        );
    }

    /**
     * @param array<AttributeGroup> $attributeGroups
     *
     * @return array{present: bool, path: ?string, methods: list<string>}
     */
    private function extractRouteAttribute(array $attributeGroups): array
    {
        foreach ($attributeGroups as $attributeGroup) {
            foreach ($attributeGroup->attrs as $attribute) {
                if (!$this->attributeShortNameMatches($attribute->name->toString(), 'Route')) {
                    continue;
                }

                $path = null;
                $methods = [];
                $positionalIndex = 0;
                foreach ($attribute->args as $arg) {
                    $argName = $arg->name?->toString();
                    if (null === $argName && 0 === $positionalIndex) {
                        $argName = 'path';
                    }

                    ++$positionalIndex;

                    if ('path' === $argName && $arg->value instanceof String_) {
                        $path = $arg->value->value;
                    }

                    if ('methods' === $argName && $arg->value instanceof Array_) {
                        $methods = $this->stringValuesFromArray($arg->value);
                    }
                }

                return ['present' => true, 'path' => $path, 'methods' => $methods];
            }
        }

        return ['present' => false, 'path' => null, 'methods' => []];
    }

    /**
     * @param array<AttributeGroup> $attributeGroups
     *
     * @return list<string>
     */
    private function extractIsGrantedValues(array $attributeGroups): array
    {
        $values = [];
        foreach ($attributeGroups as $attributeGroup) {
            foreach ($attributeGroup->attrs as $attribute) {
                if (!$this->attributeShortNameMatches($attribute->name->toString(), 'IsGranted')) {
                    continue;
                }

                foreach ($attribute->args as $arg) {
                    if ($arg->value instanceof String_) {
                        $values[] = $arg->value->value;
                        break;
                    }
                }
            }
        }

        return $values;
    }

    /**
     * @param array<AttributeGroup> $attributeGroups
     */
    private function hasIsGrantedAttribute(array $attributeGroups): bool
    {
        return [] !== $this->extractIsGrantedValues($attributeGroups);
    }

    private function methodInvokesDenyAccess(ClassMethod $classMethod, NodeFinder $nodeFinder): bool
    {
        $stmts = $classMethod->stmts;
        if (null === $stmts) {
            return false;
        }

        $methodCalls = $nodeFinder->findInstanceOf($stmts, MethodCall::class);
        foreach ($methodCalls as $methodCall) {
            if ($methodCall->name instanceof Identifier && 'denyAccessUnlessGranted' === $methodCall->name->toString()) {
                return true;
            }
        }

        return false;
    }

    private function attributeShortNameMatches(string $fullyQualifiedName, string $expectedShortName): bool
    {
        $parts = explode('\\', $fullyQualifiedName);

        return end($parts) === $expectedShortName;
    }

    /**
     * @return list<string>
     */
    private function stringValuesFromArray(Array_ $array): array
    {
        $values = [];
        foreach ($array->items as $item) {
            if ($item->value instanceof String_) {
                $values[] = $item->value->value;
            }
        }

        return $values;
    }
}
