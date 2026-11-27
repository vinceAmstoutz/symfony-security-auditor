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
use Symfony\Component\Yaml\Parser;
use Symfony\Component\Yaml\Yaml;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\MalformedProjectConfigException;

/**
 * Reads one standalone configuration file, the user's or a project's. A
 * missing file reads as empty.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class StandaloneConfigFileReader
{
    /**
     * The values a file may hold once its YAML aliases are expanded: far more
     * than any configuration holds.
     */
    public const int VALUE_LIMIT = 10_000;

    /**
     * An alias shares its anchor's values, so expanding one costs nothing:
     * VALUE_LIMIT, checked once the file is parsed, caps what is walked.
     */
    private const int UNCAPPED_ALIASES = \PHP_INT_MAX;

    private const int MAX_BYTES = 524_288;

    /**
     * How symfony/yaml 7.4.24 and later word the refusal of a file whose
     * aliases expand past its own limit, before this reader counts the values.
     */
    private const string PARSER_ALIAS_LIMIT = 'Maximum number of nodes expanded by collection aliases';

    private const int MAX_DEPTH = 32;

    /**
     * The bytes of a file's lines, each counted once per level open around
     * it, that the parser may be handed: eight times the largest file read.
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
            $parsed = Yaml::parseFile($configFile, 0, Parser::DEFAULT_MAX_NESTING_LEVEL, self::UNCAPPED_ALIASES);
        } catch (ParseException $parseException) {
            throw str_contains($parseException->getMessage(), self::PARSER_ALIAS_LIMIT) ? MalformedProjectConfigException::forOversizedConfig($configFile, self::VALUE_LIMIT) : MalformedProjectConfigException::fromParseException($configFile, $parseException);
        }

        if (!\is_array($parsed)) {
            return [];
        }

        return $this->reachesValueLimit($parsed)
            ? throw MalformedProjectConfigException::forOversizedConfig($configFile, self::VALUE_LIMIT) : $this->foldHyphenatedKeys($parsed);
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
     * Stops counting at the limit, so an expanding tree costs no more.
     *
     * @param array<array-key, mixed> $config
     */
    private function reachesValueLimit(array $config): bool
    {
        $values = new LimitIterator(new RecursiveIteratorIterator(new RecursiveArrayIterator($config), RecursiveIteratorIterator::SELF_FIRST), 0, self::VALUE_LIMIT);

        return iterator_count($values) >= self::VALUE_LIMIT;
    }

    /**
     * Folds a hyphenated key to its underscore form as `symfony/config` does,
     * so it cannot slip past the guards. Escapes a key's control characters,
     * since every refusal quotes keys back to the terminal.
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
