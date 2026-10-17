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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Diff;

use InvalidArgumentException;

/**
 * One entry of `accepted-differences.php`: a difference the maintainer
 * accepted, the scenarios it shows in (a name, or a pattern where `*` stands
 * for any run of characters, which must show the difference in every
 * scenario it names), where (a dotted path, `*` standing for one segment and
 * `**` for any number, none included), optionally what (a regular expression matched against
 * the `-line` or `+line` of a text, or against `recorded -> replayed` of a
 * value, each as JSON), why, and the bold summary of the CHANGELOG bullet
 * that announces it, or a list of them when several changes add up to it. A difference in what the scripted provider received
 * (`llm.*`: the tools offered, how files are grouped into requests) is
 * nothing a user sees: it is marked `internal` instead of citing a bullet.
 */
final readonly class AcceptedDifference
{
    private const string PROVIDER_PATH = 'llm.';

    /**
     * @param list<string> $scenarios
     * @param list<string> $changelog the bold summaries of the bullets announcing the change, none for an internal one
     */
    private function __construct(
        public array $scenarios,
        public string $path,
        public ?string $match,
        public string $reason,
        public array $changelog,
    ) {}

    /**
     * @param array<array-key, mixed> $entry
     */
    public static function fromArray(array $entry): self
    {
        $scenarios = $entry['scenarios'] ?? null;
        $path = $entry['path'] ?? null;
        $match = $entry['match'] ?? null;
        $reason = $entry['reason'] ?? null;

        if (!\is_array($scenarios) || [] === $scenarios || !array_is_list($scenarios) || \count(array_filter($scenarios, \is_string(...))) !== \count($scenarios)) {
            throw new InvalidArgumentException('An accepted difference names the scenarios it shows in as a non-empty list of names or patterns.');
        }

        if (!\is_string($path) || !\is_string($reason) || '' === trim($reason) || (null !== $match && !\is_string($match))) {
            throw new InvalidArgumentException(\sprintf('The accepted difference at "%s" needs a path and a reason.', \is_string($path) ? $path : '?'));
        }

        return new self(array_values(array_filter($scenarios, \is_string(...))), $path, $match, $reason, self::changelog($entry, $path));
    }

    public function appliesTo(string $scenario): bool
    {
        return [] !== array_filter($this->scenarios, static fn (string $pattern): bool => fnmatch($pattern, $scenario, \FNM_NOESCAPE));
    }

    public function covers(string $scenario, Difference $difference): bool
    {
        if (!$this->appliesTo($scenario) || 1 !== preg_match($this->pathPattern(), $difference->path)) {
            return false;
        }

        return null === $this->match || 1 === preg_match($this->match, $difference->subject());
    }

    public function isInternal(): bool
    {
        return [] === $this->changelog;
    }

    public function describe(): string
    {
        return \sprintf('%s%s (%s)', $this->path, null === $this->match ? '' : \sprintf(' %s', $this->match), $this->reason);
    }

    /**
     * @param array<array-key, mixed> $entry
     *
     * @return list<string>
     */
    private static function changelog(array $entry, string $path): array
    {
        $changelog = $entry['changelog'] ?? null;
        $internal = $entry['internal'] ?? false;

        if (true === $internal && null === $changelog && str_starts_with($path, self::PROVIDER_PATH)) {
            return [];
        }

        $bullets = self::bullets($changelog);
        if (false === $internal && [] !== $bullets) {
            return $bullets;
        }

        throw new InvalidArgumentException(\sprintf('The accepted difference at "%s" cites the CHANGELOG bullets that announce it, or, under llm.* only, is marked internal.', $path));
    }

    /**
     * @return list<string> the bullets cited, or none when one of them is not a non-empty text
     */
    private static function bullets(mixed $changelog): array
    {
        $bullets = \is_array($changelog) && array_is_list($changelog) ? $changelog : [$changelog];
        $texts = array_values(array_filter($bullets, static fn (mixed $bullet): bool => \is_string($bullet) && '' !== trim($bullet)));

        return \count($texts) === \count($bullets) ? array_values(array_filter($texts, \is_string(...))) : [];
    }

    private function pathPattern(): string
    {
        $pattern = strtr(preg_quote($this->path, '#'), ['\.\*\*\.' => '(?:\..+)?\.', '\*\*' => '.*', '\*' => '[^.]*']);

        return \sprintf('#^%s$#', $pattern);
    }
}
