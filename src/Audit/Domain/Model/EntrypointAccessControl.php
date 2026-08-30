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
 * One routed handler and the access checks guarding it, described by what each
 * check *is* rather than by the attribute or helper a framework spells it with.
 * A profile's parser fills it in its own terms: Symfony reads `#[Route]` into
 * `isRouted`, `#[IsGranted]` into the required attributes, and a reachable
 * `denyAccessUnlessGranted()` call into the in-body check.
 */
final readonly class EntrypointAccessControl
{
    /**
     * @param list<string> $routeMethods                    HTTP methods declared on the route, empty list when not specified
     * @param list<string> $handlerRequiredAttributes       attribute names a declarative check on the handler requires (Symfony: `#[IsGranted(...)]` on the action method)
     * @param bool         $handlerHasUnresolvedAccessCheck true when the handler carries a declarative check whose attribute is present but not resolvable to a literal string (Symfony: an enum case, `new Expression(...)`)
     * @param list<string> $classRequiredAttributes         attribute names a declarative check on the enclosing class requires
     * @param list<string> $bodyRequiredAttributes          attribute names required by an access check inside the handler body (Symfony: the first argument of `denyAccessUnlessGranted()`/`isGranted()`)
     */
    public function __construct(
        private string $filePath,
        private string $methodName,
        private ?string $routePath,
        private array $routeMethods,
        private bool $isRouted,
        private array $handlerRequiredAttributes,
        private bool $handlerChecksAccessInBody,
        private bool $classHasAccessCheck,
        private ?string $routeName = null,
        private bool $handlerHasUnresolvedAccessCheck = false,
        private array $classRequiredAttributes = [],
        private array $bodyRequiredAttributes = [],
    ) {}

    public function filePath(): string
    {
        return $this->filePath;
    }

    public function methodName(): string
    {
        return $this->methodName;
    }

    public function routePath(): ?string
    {
        return $this->routePath;
    }

    public function routeName(): ?string
    {
        return $this->routeName;
    }

    /**
     * @return list<string>
     */
    public function routeMethods(): array
    {
        return $this->routeMethods;
    }

    public function isRouted(): bool
    {
        return $this->isRouted;
    }

    /**
     * @return list<string>
     */
    public function handlerRequiredAttributes(): array
    {
        return $this->handlerRequiredAttributes;
    }

    public function handlerChecksAccessInBody(): bool
    {
        return $this->handlerChecksAccessInBody;
    }

    public function classHasAccessCheck(): bool
    {
        return $this->classHasAccessCheck;
    }

    public function handlerHasUnresolvedAccessCheck(): bool
    {
        return $this->handlerHasUnresolvedAccessCheck;
    }

    /**
     * Every authorization-rule attribute this entrypoint is guarded by, whichever
     * form the guard took — a declarative check on the handler or on its class,
     * or one inside the handler body. Lets a changed rule's dependents be found
     * without knowing which form the profile reported.
     *
     * @return list<string>
     */
    public function guardAttributes(): array
    {
        return array_values(array_unique([
            ...$this->handlerRequiredAttributes,
            ...$this->classRequiredAttributes,
            ...$this->bodyRequiredAttributes,
        ]));
    }

    /**
     * Returns a copy routed from the enclosing class's own declaration — how a
     * single-action entrypoint is routed when its handler declares no route
     * (Symfony: `#[Route]` on an invokable controller's class). Every
     * access-control flag is preserved; only the route identity and `isRouted`
     * change.
     *
     * @param list<string> $routeMethods
     */
    public function withRouteFromEnclosingClass(?string $routePath, array $routeMethods, ?string $routeName): self
    {
        return new self(
            filePath: $this->filePath,
            methodName: $this->methodName,
            routePath: $routePath,
            routeMethods: $routeMethods,
            isRouted: true,
            handlerRequiredAttributes: $this->handlerRequiredAttributes,
            handlerChecksAccessInBody: $this->handlerChecksAccessInBody,
            classHasAccessCheck: $this->classHasAccessCheck,
            routeName: $routeName,
            handlerHasUnresolvedAccessCheck: $this->handlerHasUnresolvedAccessCheck,
            classRequiredAttributes: $this->classRequiredAttributes,
            bodyRequiredAttributes: $this->bodyRequiredAttributes,
        );
    }

    public function hasAccessCheck(): bool
    {
        return $this->classHasAccessCheck
            || [] !== $this->handlerRequiredAttributes
            || $this->handlerHasUnresolvedAccessCheck
            || $this->handlerChecksAccessInBody;
    }

    public function lacksAccessCheck(): bool
    {
        return $this->isRouted && !$this->hasAccessCheck();
    }
}
