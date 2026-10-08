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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Advisory\Fixture;

use Override;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\ComposerAuditRunnerInterface;

final class WorkspaceInspectingComposerAuditRunner implements ComposerAuditRunnerInterface
{
    public int $callCount = 0;

    public ?string $workspace = null;

    public ?string $manifest = null;

    public ?string $lockfile = null;

    public ?string $workspacePermissions = null;

    public function __construct(
        private readonly string $payload = '{"advisories": {}}',
        private readonly ?Throwable $throwable = null,
    ) {}

    /**
     * @throws Throwable
     */
    #[Override]
    public function run(string $projectPath): string
    {
        ++$this->callCount;
        $this->workspace = $projectPath;
        $this->manifest = (string) file_get_contents($projectPath.'/composer.json');
        $this->lockfile = (string) file_get_contents($projectPath.'/composer.lock');
        $this->workspacePermissions = substr(\sprintf('%o', (int) fileperms($projectPath)), -4);

        if ($this->throwable instanceof Throwable) {
            throw $this->throwable;
        }

        return $this->payload;
    }
}
