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
use PhpParser\Node;
use PhpParser\Node\Expr\BinaryOp\Concat;
use PhpParser\NodeVisitorAbstract;

/**
 * Marks the outermost node of every `.` concatenation chain with the
 * `ssaConcatRoot` attribute so a rule can analyse the whole chain exactly once,
 * without depending on PHPStan's withdrawn `parent` node attribute.
 */
final class ConcatRootMarkingVisitor extends NodeVisitorAbstract
{
    public const string ROOT_ATTRIBUTE = 'ssaConcatRoot';

    private int $concatDepth = 0;

    #[Override]
    public function enterNode(Node $node): ?Node
    {
        if (!$node instanceof Concat) {
            return null;
        }

        if (0 === $this->concatDepth) {
            $node->setAttribute(self::ROOT_ATTRIBUTE, true);
        }

        ++$this->concatDepth;

        return null;
    }

    #[Override]
    public function leaveNode(Node $node): ?Node
    {
        if ($node instanceof Concat) {
            --$this->concatDepth;
        }

        return null;
    }
}
