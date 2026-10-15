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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Scenario;

use Override;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Runner\Workspace;

final readonly class ChangeMode implements SetupActionInterface
{
    public function __construct(
        private string $path,
        private int $mode,
    ) {}

    #[Override]
    public function apply(Workspace $workspace): void
    {
        (new Filesystem())->chmod($workspace->resolve($this->path), $this->mode);
    }
}
