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
 * Writes a file of the workspace; its path and its content may hold the
 * `{workspace}` and `{project}` placeholders.
 */
final readonly class WriteFile implements SetupActionInterface
{
    public function __construct(
        private string $path,
        private string $content,
    ) {}

    #[Override]
    public function apply(Workspace $workspace): void
    {
        (new Filesystem())->dumpFile($workspace->resolve($this->path), $workspace->expand($this->content));
    }
}
