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

/**
 * How an output or a file is kept in a recording: a JSON document as its
 * decoded structure, so a difference names the key that changed; any other
 * text as its lines; bytes that are not UTF-8 as base64; a directory as the
 * snapshot of each file under it.
 */
final readonly class Snapshot
{
    /**
     * @return array{json: mixed}|array{lines: list<string>}|array{base64: string}
     */
    public static function ofText(string $text, Normalizer $normalizer): array
    {
        if (!mb_check_encoding($text, 'UTF-8')) {
            return ['base64' => base64_encode($text)];
        }

        $normalized = $normalizer->text($text);
        $decoded = json_decode(trim($normalized), true);
        if ((\is_array($decoded) && '' !== trim($normalized)) || \in_array(trim($normalized), ['true', 'false', 'null'], true)) {
            return ['json' => $normalizer->value($decoded)];
        }

        return ['lines' => $normalizer->lines($text)];
    }

    /**
     * @return array<string, mixed>|null
     */
    public static function ofPath(string $path, Normalizer $normalizer): ?array
    {
        if (is_link($path)) {
            return ['link' => $normalizer->text((string) readlink($path))];
        }

        if (is_dir($path)) {
            return ['directory' => self::ofDirectory($path, $normalizer)];
        }

        if (!is_file($path)) {
            return null;
        }

        return self::ofText((string) file_get_contents($path), $normalizer);
    }

    /**
     * @return array<string, array<string, mixed>|null>
     */
    private static function ofDirectory(string $directory, Normalizer $normalizer): array
    {
        $files = [];
        /** @var SplFileInfo $fileInfo */
        foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS)) as $fileInfo) {
            $files[substr($fileInfo->getPathname(), \strlen($directory) + 1)] = self::ofPath($fileInfo->getPathname(), $normalizer);
        }

        ksort($files);

        return $files;
    }
}
