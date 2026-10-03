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
