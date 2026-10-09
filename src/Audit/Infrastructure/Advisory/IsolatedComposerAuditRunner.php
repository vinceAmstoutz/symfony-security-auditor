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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory;

use Override;
use Symfony\Component\Filesystem\Exception\IOException;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\Exception\AdvisorySourceUnavailableException;

use function Symfony\Component\String\b;

/**
 * Runs the decorated `composer audit` outside the audited project. Composer
 * reads the `composer.json` of the directory it runs in, and the project's
 * `repositories` decide where it fetches advisories from: a repository under
 * audit could point it at a feed of its own that reports nothing, or at an
 * internal address of the audit host. The decorated runner is therefore given
 * a private temporary directory holding a copy of the project's `composer.lock`
 * (the only file `audit --locked` reads of the project) and an empty
 * `composer.json`, removed once the audit is done. The user's own Composer
 * configuration (`COMPOSER_HOME`) still applies.
 *
 * A lockfile that is missing, a symlink or larger than `MAX_LOCKFILE_BYTES` is
 * refused before it is read: the project is untrusted, and a `composer.lock`
 * symlinked to `/dev/zero` must not be copied.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class IsolatedComposerAuditRunner implements ComposerAuditRunnerInterface
{
    public const int MAX_LOCKFILE_BYTES = 8_388_608;

    private const string EMPTY_MANIFEST = "{}\n";

    private const int WORKSPACE_MODE = 0o700;

    public function __construct(
        private ComposerAuditRunnerInterface $composerAuditRunner,
        private Filesystem $filesystem,
    ) {}

    #[Override]
    public function run(string $projectPath): string
    {
        $lockfile = $this->lockfileOf($projectPath);
        $workspace = $this->createWorkspace();

        try {
            $this->filesystem->dumpFile(\sprintf('%s/composer.json', $workspace), self::EMPTY_MANIFEST);
            $this->filesystem->dumpFile(\sprintf('%s/composer.lock', $workspace), $lockfile);

            return $this->composerAuditRunner->run($workspace);
        } finally {
            $this->filesystem->remove($workspace);
        }
    }

    /**
     * @throws AdvisorySourceUnavailableException
     */
    private function lockfileOf(string $projectPath): string
    {
        $lockfilePath = \sprintf('%s/composer.lock', b($projectPath)->trimEnd('/')->toString());

        if (!$this->filesystem->exists($lockfilePath)) {
            throw AdvisorySourceUnavailableException::forUnusableLockfile($projectPath, 'composer.lock does not exist');
        }

        if (is_link($lockfilePath)) {
            throw AdvisorySourceUnavailableException::forUnusableLockfile($projectPath, 'composer.lock is a symlink');
        }

        $bytes = filesize($lockfilePath);
        \assert(false !== $bytes, 'filesize() must succeed for a path exists() already confirmed present');

        if ($bytes > self::MAX_LOCKFILE_BYTES) {
            throw AdvisorySourceUnavailableException::forUnusableLockfile($projectPath, \sprintf('composer.lock is larger than %d bytes', self::MAX_LOCKFILE_BYTES));
        }

        try {
            return $this->filesystem->readFile($lockfilePath);
        } catch (IOException $ioException) {
            throw AdvisorySourceUnavailableException::forUnusableLockfile($projectPath, $ioException->getMessage(), $ioException);
        }
    }

    private function createWorkspace(): string
    {
        $workspace = \sprintf('%s/symfony-security-auditor-composer-%s', sys_get_temp_dir(), bin2hex(random_bytes(8)));
        $this->filesystem->mkdir($workspace, self::WORKSPACE_MODE);

        return $workspace;
    }
}
