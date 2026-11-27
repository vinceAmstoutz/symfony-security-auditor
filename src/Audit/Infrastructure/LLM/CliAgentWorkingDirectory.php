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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM;

use Symfony\Component\Filesystem\Filesystem;

/**
 * A fresh directory of the system temp directory that only the user running
 * the audit can open, removed with what it holds once nothing holds this
 * object.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class CliAgentWorkingDirectory
{
    private const int PRIVATE_DIRECTORY_MODE = 0o700;

    public string $path;

    public function __construct()
    {
        $this->path = \sprintf('%s/symfony-security-auditor-cli-%s', sys_get_temp_dir(), bin2hex(random_bytes(16)));
        (new Filesystem())->mkdir($this->path, self::PRIVATE_DIRECTORY_MODE);
    }

    public function __destruct()
    {
        (new Filesystem())->remove($this->path);
    }
}
