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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model;

/**
 * One `access_control` rule as the application declares it: the path pattern
 * or route it targets, the HTTP methods it is limited to, and whether it
 * checks anything, which it does only with roles or an expression. The
 * application applies the first rule that matches a request.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class AccessControlRule
{
    /**
     * @param string       $target    the path pattern, or `route: <name>`
     * @param list<string> $methods   upper-case; empty for every method
     * @param bool         $restricts whether the rule names roles or an expression
     */
    public function __construct(
        public string $target,
        public array $methods,
        public bool $restricts,
    ) {}
}
