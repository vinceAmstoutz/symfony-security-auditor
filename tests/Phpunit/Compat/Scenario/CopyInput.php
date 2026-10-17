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

/**
 * Copies a committed input of the suite — a configuration file a release
 * documented, for instance — into the workspace.
 */
final readonly class CopyInput implements SetupActionInterface
{
    public function __construct(
        private string $input,
        private string $path,
    ) {}

    #[Override]
    public function apply(Workspace $workspace): void
    {
        (new Filesystem())->copy(\sprintf('%s/Input/%s', __DIR__, $this->input), $workspace->resolve($this->path), true);
    }
}
