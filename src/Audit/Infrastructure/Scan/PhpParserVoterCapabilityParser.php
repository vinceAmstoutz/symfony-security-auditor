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
use PhpParser\Node\Scalar\String_;
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
    #[Override]
    public function parse(ProjectFile $projectFile): ?VoterCapability
    {
        if (ProjectFileType::VOTER !== $projectFile->fileType()) {
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
        $class = $nodeFinder->findFirstInstanceOf($ast, Class_::class);
        if (!$class instanceof Class_) {
            return null;
        }

        $supportsMethod = $this->findSupportsMethod($class);
        if (!$supportsMethod instanceof ClassMethod) {
            return null;
        }

        $body = $supportsMethod->stmts;
        if (null === $body) {
            return null;
        }

        $attributes = $this->collectStringLiterals($body, $nodeFinder);
        $subjects = $this->collectInstanceofClassNames($body, $nodeFinder);

        return new VoterCapability(
            filePath: $projectFile->relativePath(),
            className: $this->resolveClassName($class),
            supportedAttributes: $attributes,
            supportedSubjects: $subjects,
        );
    }

    private function findSupportsMethod(Class_ $class): ?ClassMethod
    {
        foreach ($class->getMethods() as $classMethod) {
            if ('supports' === $classMethod->name->toString()) {
                return $classMethod;
            }
        }

        return null;
    }

    /**
     * @param array<Node> $body
     *
     * @return list<string>
     */
    private function collectStringLiterals(array $body, NodeFinder $nodeFinder): array
    {
        $values = [];
        $stringNodes = $nodeFinder->findInstanceOf($body, String_::class);
        foreach ($stringNodes as $stringNode) {
            $value = $stringNode->value;
            if ('' === $value) {
                continue;
            }

            if (\in_array($value, $values, true)) {
                continue;
            }

            $values[] = $value;
        }

        return $values;
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
