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

final readonly class RouteAccessControl
{
    /**
     * @param list<string> $routeMethods         HTTP methods declared on the route, empty list when not specified
     * @param list<string> $methodLevelIsGranted attribute names referenced by `#[IsGranted(...)]` on the action method
     */
    public function __construct(
        private string $filePath,
        private string $methodName,
        private ?string $routePath,
        private array $routeMethods,
        private bool $hasRouteAttribute,
        private array $methodLevelIsGranted,
        private bool $methodHasDenyAccess,
        private bool $classHasIsGranted,
        private ?string $routeName = null,
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

    public function hasRouteAttribute(): bool
    {
        return $this->hasRouteAttribute;
    }

    /**
     * @return list<string>
     */
    public function methodLevelIsGranted(): array
    {
        return $this->methodLevelIsGranted;
    }

    public function methodHasDenyAccess(): bool
    {
        return $this->methodHasDenyAccess;
    }

    public function classHasIsGranted(): bool
    {
        return $this->classHasIsGranted;
    }

    public function hasAccessCheck(): bool
    {
        return $this->classHasIsGranted
            || [] !== $this->methodLevelIsGranted
            || $this->methodHasDenyAccess;
    }

    public function lacksAccessCheck(): bool
    {
        return $this->hasRouteAttribute && !$this->hasAccessCheck();
    }
}
