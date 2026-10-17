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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Runner;

use Symfony\Component\Filesystem\Filesystem;
use UnexpectedValueException;

/**
 * The directory a scenario runs in, created afresh, under a name no other run
 * shares, for each run. Its path differs from one run to the next, so the
 * normalizer replaces it with `<WORKSPACE>`, but always has the same length,
 * so the console wraps a line that holds it at the same place:
 *
 * - `project/` the audited project
 * - `home/` the standalone binary's XDG directories (`config/`, `cache/`, `data/`)
 * - `kernel/` the bundle kernel's project, cache and log directories
 * - `bin/` the executables put first on `PATH`
 *
 * A scenario reads and writes nothing outside it: a path a step, a setup action
 * or an artifact names outside the workspace is refused. The one exception is
 * `{null-device}`, the discard device a report can be written to: the real
 * `/dev/null` for a process that cannot write `/dev`, and a device node of its
 * own under the workspace for one that can, so a release that replaces its
 * output file through a rename never replaces the system's.
 */
final readonly class Workspace
{
    public const string NULL_DEVICE = '{null-device}';

    private const string PREFIX = 'ssa-compat-';

    private const string DIRECTORY = 'w';

    private const int ROOT_LENGTH = 48;

    private const int SHORTEST_SUFFIX = 12;

    private const string SYSTEM_NULL_DEVICE = '/dev/null';

    private const string OWN_NULL_DEVICE = 'null';

    private function __construct(
        public string $root,
    ) {}

    /**
     * @throws UnexpectedValueException when the temporary directory's path is too long for a workspace of the fixed length
     */
    public static function create(): self
    {
        $base = rtrim((string) realpath(sys_get_temp_dir()), '/');
        $suffixLength = self::ROOT_LENGTH - \strlen(\sprintf('%s/%s/%s', $base, self::PREFIX, self::DIRECTORY));
        if ($suffixLength < self::SHORTEST_SUFFIX) {
            throw new UnexpectedValueException(\sprintf('The compatibility suite puts every workspace at a path of %d characters, so the console wraps its output as it did when recording, and "%s" leaves no room for it: set TMPDIR to a directory of at most %d characters.', self::ROOT_LENGTH, $base, \strlen($base) + $suffixLength - self::SHORTEST_SUFFIX));
        }

        $parent = \sprintf('%s/%s%s', $base, self::PREFIX, substr(bin2hex(random_bytes(self::ROOT_LENGTH)), 0, $suffixLength));
        (new Filesystem())->mkdir($parent, 0o700);
        $workspace = new self(\sprintf('%s/%s', $parent, self::DIRECTORY));
        (new Filesystem())->mkdir([$workspace->projectDir(), $workspace->resolve('home'), $workspace->resolve('kernel'), $workspace->resolve('bin')]);

        return $workspace;
    }

    public function projectDir(): string
    {
        return \sprintf('%s/project', $this->root);
    }

    /**
     * @throws UnexpectedValueException when the path lies outside the workspace
     */
    public function resolve(string $path): string
    {
        $expanded = $this->expand($path);

        return $this->confined(str_starts_with($expanded, '/') ? $expanded : \sprintf('%s/%s', $this->root, $expanded));
    }

    public function expand(string $text): string
    {
        return strtr($text, ['{workspace}' => $this->root, '{project}' => $this->projectDir(), self::NULL_DEVICE => $this->nullDevice()]);
    }

    /**
     * @throws UnexpectedValueException when the value is an absolute path outside the workspace
     */
    public function confined(string $value): string
    {
        if (!str_starts_with($value, '/') || $value === $this->nullDevice() || $this->holds($value)) {
            return $value;
        }

        throw new UnexpectedValueException(\sprintf('A scenario only touches its workspace, and "%s" lies outside "%s".', $value, $this->root));
    }

    public function nullDevice(): string
    {
        return self::canWriteSystemDevices() ? \sprintf('%s/%s', $this->root, self::OWN_NULL_DEVICE) : self::SYSTEM_NULL_DEVICE;
    }

    public static function canWriteSystemDevices(): bool
    {
        return is_writable(\dirname(self::SYSTEM_NULL_DEVICE));
    }

    /**
     * Removes the workspace and the private directory that holds it, which is
     * where the removal moves it first, out of every other process's reach.
     */
    public function remove(): void
    {
        $filesystem = new Filesystem();
        $filesystem->remove($this->root);
        $filesystem->remove(\dirname($this->root));
    }

    private function holds(string $path): bool
    {
        $inside = $path === $this->root || str_starts_with($path, \sprintf('%s/', $this->root));

        return $inside && !\in_array('..', explode('/', $path), true);
    }
}
