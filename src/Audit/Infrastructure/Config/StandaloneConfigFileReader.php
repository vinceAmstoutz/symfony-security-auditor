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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config;

use LimitIterator;
use RecursiveArrayIterator;
use RecursiveIteratorIterator;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Yaml\Exception\ParseException;
use Symfony\Component\Yaml\Yaml;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\MalformedProjectConfigException;

/**
 * Reads one standalone configuration file — the user's or the project's —
 * into the array the loader layers and guards. A missing file reads as empty.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class StandaloneConfigFileReader
{
    /**
     * Far more than any configuration holds. A YAML alias names a node rather
     * than repeating it, so a few hundred bytes of nested aliases parse
     * cheaply into a billion values that only walking the tree expands.
     */
    public const int VALUE_LIMIT = 10_000;

    private const int MAX_BYTES = 524_288;

    private const int MAX_DEPTH = 32;

    /**
     * Eight times the largest file read, which no configuration comes near:
     * the parser keeps a few copies of each block it opens, so this bounds
     * what any file it is handed can take, whatever its shape.
     */
    private const int MAX_NESTED_BYTES = 4_194_304;

    /**
     * @return array<array-key, mixed>
     *
     * @throws MalformedProjectConfigException
     */
    public function read(string $configFile): array
    {
        if (!is_file($configFile)) {
            return [];
        }

        $this->assertParseable($configFile);

        try {
            $parsed = Yaml::parseFile($configFile);
        } catch (ParseException $parseException) {
            throw MalformedProjectConfigException::fromParseException($configFile, $parseException);
        }

        if (!\is_array($parsed)) {
            return [];
        }

        if ($this->reachesValueLimit($parsed)) {
            throw MalformedProjectConfigException::forOversizedConfig($configFile, self::VALUE_LIMIT);
        }

        return $this->foldHyphenatedKeys($parsed);
    }

    /**
     * @throws MalformedProjectConfigException
     */
    private function assertParseable(string $configFile): void
    {
        $bytes = filesize($configFile);
        \assert(false !== $bytes, 'filesize() must succeed for a file is_file() found');

        if ($bytes > self::MAX_BYTES) {
            throw MalformedProjectConfigException::forOversizedFile($configFile, self::MAX_BYTES);
        }

        if (is_readable($configFile)) {
            $this->assertShallowEnough($configFile, YamlNesting::of((new Filesystem())->readFile($configFile), self::MAX_DEPTH));
        }
    }

    /**
     * @throws MalformedProjectConfigException
     */
    private function assertShallowEnough(string $configFile, YamlNesting $yamlNesting): void
    {
        if ($yamlNesting->depth > self::MAX_DEPTH) {
            throw MalformedProjectConfigException::forDeeplyNestedFile($configFile, self::MAX_DEPTH);
        }

        if ($yamlNesting->nestedBytes > self::MAX_NESTED_BYTES) {
            throw MalformedProjectConfigException::forHeavilyNestedFile($configFile, self::MAX_NESTED_BYTES);
        }
    }

    /**
     * Walks the values lazily, nested ones included, and stops at the limit,
     * so counting an expanding tree costs no more than the limit itself.
     *
     * @param array<array-key, mixed> $config
     */
    private function reachesValueLimit(array $config): bool
    {
        $values = new LimitIterator(new RecursiveIteratorIterator(new RecursiveArrayIterator($config), RecursiveIteratorIterator::SELF_FIRST), 0, self::VALUE_LIMIT);

        return iterator_count($values) >= self::VALUE_LIMIT;
    }

    /**
     * `symfony/config` reads `secret-scrubbing` as `secret_scrubbing` when it
     * normalizes the tree, after the loader's guards ran on the raw keys;
     * folding the same way first keeps a hyphenated spelling from slipping
     * past them.
     * A key is also quoted back by every refusal, so its control characters
     * are escaped here: a repository's config cannot send escape sequences,
     * eight-bit ones included, to the terminal through a key no valid config
     * uses.
     *
     * @param array<array-key, mixed> $config
     *
     * @return array<array-key, mixed>
     */
    private function foldHyphenatedKeys(array $config): array
    {
        $folded = [];
        foreach ($config as $key => $value) {
            $folded[\is_string($key) ? $this->foldedKey($key, $config) : $key] = \is_array($value) ? $this->foldHyphenatedKeys($value) : $value;
        }

        return $folded;
    }

    /**
     * @param array<array-key, mixed> $siblings
     */
    private function foldedKey(string $key, array $siblings): string
    {
        $underscored = str_replace('-', '_', $key);
        $foldedKey = str_contains($key, '-') && !str_contains($key, '_') && !\array_key_exists($underscored, $siblings) ? $underscored : $key;

        return TerminalText::escaped($foldedKey);
    }
}
