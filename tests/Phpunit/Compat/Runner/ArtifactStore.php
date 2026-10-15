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

use FilesystemIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;
use Symfony\Component\Filesystem\Filesystem;

/**
 * Keeps the exact bytes of the files a recorded release wrote while preparing
 * a scenario, the workspace path written as `{workspace}`, and writes them
 * back before a replay.
 */
final readonly class ArtifactStore
{
    /**
     * @param list<string> $paths workspace-relative files or directories
     *
     * @return array<string, array{mode: string, base64: string}> each file's permissions and content, by workspace-relative path
     */
    public static function capture(Workspace $workspace, array $paths): array
    {
        $artifacts = [];
        foreach ($paths as $path) {
            foreach (self::filesUnder($workspace->resolve($path)) as $file) {
                $content = strtr((string) file_get_contents($file), [$workspace->root => '{workspace}', str_replace('/', '\/', $workspace->root) => '{workspace-json}']);
                $artifacts[substr($file, \strlen($workspace->root) + 1)] = ['mode' => decoct(fileperms($file) & 0o777), 'base64' => base64_encode($content)];
            }
        }

        ksort($artifacts);

        return $artifacts;
    }

    /**
     * @param array<string, array{mode: string, base64: string}> $artifacts
     */
    public static function restore(Workspace $workspace, array $artifacts): void
    {
        $filesystem = new Filesystem();
        foreach ($artifacts as $path => $artifact) {
            $content = strtr((string) base64_decode($artifact['base64'], true), ['{workspace}' => $workspace->root, '{workspace-json}' => str_replace('/', '\/', $workspace->root)]);
            $filesystem->dumpFile($workspace->resolve($path), $content);
            $filesystem->chmod($workspace->resolve($path), (int) octdec($artifact['mode']));
        }
    }

    /**
     * @return list<string>
     */
    private static function filesUnder(string $path): array
    {
        if (is_file($path)) {
            return [$path];
        }

        if (!is_dir($path)) {
            return [];
        }

        $files = [];
        /** @var SplFileInfo $fileInfo */
        foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS)) as $fileInfo) {
            if ($fileInfo->isFile()) {
                $files[] = $fileInfo->getPathname();
            }
        }

        sort($files);

        return $files;
    }
}
