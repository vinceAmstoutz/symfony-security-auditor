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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tooling\PHPStan;

use Override;
use PhpParser\Comment\Doc;
use PhpParser\Node;
use PhpParser\Node\Stmt\ClassLike;
use PHPStan\Analyser\Scope;
use PHPStan\Rules\IdentifierRuleError;
use PHPStan\Rules\Rule;
use PHPStan\Rules\RuleErrorBuilder;
use PHPStan\ShouldNotHappenException;

/**
 * Enforces `.claude/rules/no-comments.md`: a docblock past a handful of prose
 * lines is design rationale that belongs in named methods, named constants or
 * tests. Annotation lines never count, so type information stays free.
 *
 * @implements Rule<ClassLike>
 */
final readonly class OversizedDocblockRule implements Rule
{
    public function __construct(private int $maxProseLines) {}

    #[Override]
    public function getNodeType(): string
    {
        return ClassLike::class;
    }

    /**
     * @return list<IdentifierRuleError>
     *
     * @throws ShouldNotHappenException
     */
    #[Override]
    public function processNode(Node $node, Scope $scope): array
    {
        $errors = [];
        foreach ([$node, ...$node->stmts] as $documented) {
            $error = $this->errorFor($documented->getDocComment());
            if ($error instanceof IdentifierRuleError) {
                $errors[] = $error;
            }
        }

        return $errors;
    }

    /**
     * @throws ShouldNotHappenException
     */
    private function errorFor(?Doc $doc): ?IdentifierRuleError
    {
        if (!$doc instanceof Doc) {
            return null;
        }

        $proseLineCount = $this->countProseLines($doc->getText());
        if ($proseLineCount <= $this->maxProseLines) {
            return null;
        }

        return RuleErrorBuilder::message(\sprintf(
            'Docblock has %d prose lines, more than the %d allowed. Move the explanation into named methods, a named constant or a test, and keep only what cannot be read from the code.',
            $proseLineCount,
            $this->maxProseLines,
        ))
            ->identifier('ssa.oversizedDocblock')
            ->line($doc->getStartLine())
            ->build();
    }

    private function countProseLines(string $docComment): int
    {
        $proseLineCount = 0;
        $unclosedBraces = 0;
        foreach (explode("\n", $docComment) as $line) {
            $stripped = trim(ltrim(trim($line), '/*'));
            if ($unclosedBraces > 0) {
                $unclosedBraces += $this->braceBalance($stripped);

                continue;
            }

            if (str_starts_with($stripped, '@')) {
                $unclosedBraces = max(0, $this->braceBalance($stripped));

                continue;
            }

            if ('' !== $stripped) {
                ++$proseLineCount;
            }
        }

        return $proseLineCount;
    }

    private function braceBalance(string $line): int
    {
        return substr_count($line, '{') - substr_count($line, '}');
    }
}
