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

use Composer\InstalledVersions;

/**
 * Removes what differs between two runs of the same release: the workspace
 * and checkout paths, the discard device, the clock and the date, run identifiers,
 * durations, the PHP version and the versions of the packages the binary
 * prints or pins, and the line numbers of an uncaught exception's origin.
 */
final readonly class Normalizer
{
    private const array PATTERNS = [
        '/\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?/' => '<TIMESTAMP>',
        '/\b\d{4}-\d{2}-\d{2}\b/' => '<DATE>',
        '/AUDIT-[0-9A-F]{8}/' => 'AUDIT-<ID>',
        '/\bIn (\S+) line \d+:/' => 'In $1 line <LINE>:',
        '/(Duration:?\s*)\d+(?:\.\d+)?\s?(ms|s|seconds)\b/i' => '$1<DURATION>',
        '/\b\d+(?:\.\d+)?\s?(ms|s|seconds)(\s+elapsed)\b/' => '<DURATION>$2',
        '/(in )\d+(?:\.\d+)?s\b/' => '$1<DURATION>',
        '/(\*\*Duration:\*\*\s*)\d+(?:\.\d+)?s\b/' => '$1<DURATION>',
        '/\b\d+\.\d+s\b/' => '<DURATION>',
    ];

    private const array VOLATILE_KEYS = ['duration_seconds' => 0, 'durationSeconds()' => 0];

    private const string LINE_BREAK_IN_A_BLOCK = '(?: *\R[ !]*)?';

    private const array VERSIONED_PACKAGES = [
        'vinceamstoutz/symfony-security-auditor' => '<VERSION>',
        'symfony/ai-platform' => '<PACKAGE-VERSION>',
        'symfony/ai-bundle' => '<PACKAGE-VERSION>',
        'symfony/models-dev' => '<PACKAGE-VERSION>',
    ];

    /**
     * @param array<string, string> $replacements     literal text to replace, longest first
     * @param string                $wrappedWorkspace the workspace path, as a pattern that also matches it broken over two lines of a console block
     */
    private function __construct(
        private array $replacements,
        private string $wrappedWorkspace,
    ) {}

    public static function for(Workspace $workspace): self
    {
        $treeRoot = \dirname(InstalledVersions::getRootPackage()['install_path']);
        $realTreeRoot = realpath($treeRoot);

        $replacements = [
            $workspace->nullDevice() => '<NULL-DEVICE>',
            $workspace->root => '<WORKSPACE>',
            str_replace('/', '\/', $workspace->root) => '<WORKSPACE>',
            false === $realTreeRoot ? $treeRoot : $realTreeRoot => '<TREE>',
            \PHP_VERSION => '<PHP-VERSION>',
        ];

        foreach (self::VERSIONED_PACKAGES as $package => $placeholder) {
            $version = InstalledVersions::isInstalled($package) ? InstalledVersions::getPrettyVersion($package) : null;
            if (null !== $version && '' !== $version) {
                $replacements[$version] = $placeholder;
            }
        }

        uksort($replacements, static fn (string $left, string $right): int => \strlen($right) <=> \strlen($left));

        return new self($replacements, self::wrapped($workspace->root));
    }

    public function text(string $text): string
    {
        $replaced = strtr((string) preg_replace($this->wrappedWorkspace, '<WORKSPACE>', $text), $this->replacements);

        return (string) preg_replace(array_keys(self::PATTERNS), array_values(self::PATTERNS), $replaced);
    }

    /**
     * A console block breaks a word longer than its width wherever the width
     * ends, so a path can continue on the next line after the block's margin.
     */
    private static function wrapped(string $path): string
    {
        $characters = array_map(static fn (string $character): string => preg_quote($character, '#'), str_split($path));

        return \sprintf('#%s#', implode(self::LINE_BREAK_IN_A_BLOCK, $characters));
    }

    /**
     * @return list<string>
     */
    public function lines(string $text): array
    {
        return array_map(rtrim(...), explode("\n", rtrim($this->text($text))));
    }

    public function value(mixed $value): mixed
    {
        if (\is_string($value)) {
            return $this->text($value);
        }

        return \is_array($value) ? $this->entries($value) : $value;
    }

    /**
     * @param array<array-key, mixed> $entries
     *
     * @return array<array-key, mixed>
     */
    private function entries(array $entries): array
    {
        $normalized = [];
        foreach ($entries as $key => $item) {
            if (\is_int($key)) {
                $normalized[$key] = $this->value($item);

                continue;
            }

            $normalized[$this->text($key)] = \array_key_exists($key, self::VOLATILE_KEYS) ? self::VOLATILE_KEYS[$key] : $this->value($item);
        }

        return $normalized;
    }
}
