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

use Override;
use PhpParser\Node;
use PhpParser\Node\Expr\Instanceof_;
use PhpParser\Node\Name;
use PhpParser\Node\Stmt\Class_;
use PhpParser\Node\Stmt\ClassMethod;
use PhpParser\NodeFinder;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitor\NameResolver;
use PhpParser\ParserFactory;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VoterCapability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\VoterCapabilityParserInterface;

/**
 * @internal not part of the BC promise — see docs/versioning.md
 *
 * Walks a voter file's AST and approximates its `supports()` vocabulary by
 * collecting every string literal (attribute names) and every `instanceof X`
 * right-hand class name (subject types) inside the method body. The result is
 * heuristic — random string literals inside `supports()` will be reported as
 * attributes — but for the attacker prompt's "Voter Coverage" block it gives
 * the LLM a useful, deterministic summary of who handles what.
 */
final readonly class PhpParserVoterCapabilityParser implements VoterCapabilityParserInterface
{
    public function __construct(
        private ThisCallReachability $thisCallReachability = new ThisCallReachability(),
        private VoterSupportedAttributeCollector $voterSupportedAttributeCollector = new VoterSupportedAttributeCollector(),
        private NestingDepthGuard $nestingDepthGuard = new NestingDepthGuard(),
    ) {}

    #[Override]
    public function parse(ProjectFile $projectFile): ?VoterCapability
    {
        if (ProjectFileType::VOTER !== $projectFile->fileType() || !$this->nestingDepthGuard->admits($projectFile)) {
            return null;
        }

        try {
            $parserFactory = new ParserFactory();
            $parser = $parserFactory->createForNewestSupportedVersion();
            $ast = $parser->parse($projectFile->content()) ?? [];

            $nodeTraverser = new NodeTraverser();
            $nodeTraverser->addVisitor(new NameResolver());
            $ast = $nodeTraverser->traverse($ast);
        } catch (Throwable) {
            return null;
        }

        $nodeFinder = new NodeFinder();
        $voter = $this->findVoterClass($nodeFinder->findInstanceOf($ast, Class_::class));
        if (null === $voter) {
            return null;
        }

        [$class, $supportsMethod] = $voter;

        if (null === $supportsMethod->stmts) {
            return null;
        }

        $methodsByName = $this->methodsByName($class);
        $body = $this->thisCallReachability->reachableBody($supportsMethod, $methodsByName);
        $body = [...$body, ...$this->voteOnAttributeBody($class, $methodsByName)];

        $attributes = $this->voterSupportedAttributeCollector->collect($body, $class);
        $subjects = $this->collectInstanceofClassNames($body, $nodeFinder);

        return new VoterCapability(
            filePath: $projectFile->relativePath(),
            className: $this->resolveClassName($class),
            supportedAttributes: $attributes,
            supportedSubjects: $subjects,
        );
    }

    /**
     * A voter file may declare helper classes alongside the voter itself
     * (e.g. a small attribute-constants holder); the voter is whichever class
     * actually has a `supports()` method, not necessarily the first one. A
     * voter implementing `VoterInterface` directly (rather than extending the
     * abstract `Voter` class) has no `supports()` at all — its capability
     * vocabulary lives inline in `vote()` instead, so that method is tried as
     * a fallback source for the same string-literal/instanceof heuristics.
     *
     * @param array<Class_> $classes
     *
     * @return array{Class_, ClassMethod}|null
     */
    private function findVoterClass(array $classes): ?array
    {
        foreach ($classes as $class) {
            $capabilityMethod = $this->findMethodNamed($class, 'supports') ?? $this->findMethodNamed($class, 'vote');
            if ($capabilityMethod instanceof ClassMethod) {
                return [$class, $capabilityMethod];
            }
        }

        return null;
    }

    private function findMethodNamed(Class_ $class, string $methodName): ?ClassMethod
    {
        foreach ($class->getMethods() as $classMethod) {
            if ($methodName === $classMethod->name->toString()) {
                return $classMethod;
            }
        }

        return null;
    }

    /**
     * The abstract Symfony `Voter` class's canonical style checks only the
     * subject type in `supports()` and dispatches on the attribute inside
     * `voteOnAttribute()` instead — that attribute vocabulary would otherwise
     * be invisible to the string-literal/instanceof heuristics, which only
     * ever look at whichever method `findVoterClass()` returned.
     *
     * @param array<string, ClassMethod> $methodsByName
     *
     * @return array<Node>
     */
    private function voteOnAttributeBody(Class_ $class, array $methodsByName): array
    {
        $voteOnAttributeMethod = $this->findMethodNamed($class, 'voteOnAttribute');
        if (!$voteOnAttributeMethod instanceof ClassMethod || null === $voteOnAttributeMethod->stmts) {
            return [];
        }

        return $this->thisCallReachability->reachableBody($voteOnAttributeMethod, $methodsByName);
    }

    /**
     * @return array<string, ClassMethod>
     */
    private function methodsByName(Class_ $class): array
    {
        $methodsByName = [];
        foreach ($class->getMethods() as $classMethod) {
            $methodsByName[$classMethod->name->toString()] = $classMethod;
        }

        return $methodsByName;
    }

    /**
     * @param array<Node> $body
     *
     * @return list<string>
     */
    private function collectInstanceofClassNames(array $body, NodeFinder $nodeFinder): array
    {
        $names = [];
        $instanceofNodes = $nodeFinder->findInstanceOf($body, Instanceof_::class);
        foreach ($instanceofNodes as $instanceofNode) {
            $classExpression = $instanceofNode->class;
            if (!$classExpression instanceof Name) {
                continue;
            }

            $resolved = $classExpression->toString();
            if (\in_array($resolved, $names, true)) {
                continue;
            }

            $names[] = $resolved;
        }

        return $names;
    }

    private function resolveClassName(Class_ $class): string
    {
        $namespaceName = $class->namespacedName;
        if ($namespaceName instanceof Name) {
            return $namespaceName->toString();
        }

        $shortName = $class->name?->toString();

        return null === $shortName ? '' : $shortName;
    }
}
