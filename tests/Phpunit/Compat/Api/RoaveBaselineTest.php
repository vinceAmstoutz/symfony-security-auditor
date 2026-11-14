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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Api;

use DOMComment;
use DOMDocument;
use DOMElement;
use DOMText;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileType;
use VinceAmstoutz\SymfonySecurityAuditor\Command\OutputFormat;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\UnreleasedChangelog;

/**
 * Every break `.roave-backward-compatibility-check.xml` accepts is one line
 * the API compatibility job reported, written as that line, and announced by
 * a bullet under `## [Unreleased]` in `CHANGELOG.md`, named in the comment
 * right before it: a wildcard could accept a break nobody looked at. The one
 * exception is the pattern docs/versioning.md stands behind, a case added to
 * a Domain model enum, pinned here so it never accepts more.
 */
final class RoaveBaselineTest extends TestCase
{
    private const string BASELINE = __DIR__.'/../../../../.roave-backward-compatibility-check.xml';

    private const string ANNOUNCEMENT = '/^\s*CHANGELOG: "(.+)"\s*$/s';

    private const string REPORTED_LINE = '/^#\\\\\[BC\\\\\] [A-Z]+: .+#$/';

    private const string METACHARACTERS = '.^$*+?()[]{}|#';

    private const string ADDED_DOMAIN_ENUM_CASE = '#\[BC\] ADDED: Case VinceAmstoutz\\\\SymfonySecurityAuditor\\\\Audit\\\\Domain\\\\Model\\\\\w+::\w+ was added#';

    public function test_the_baseline_accepts_the_cases_a_domain_enum_gains_as_its_policy_allows(): void
    {
        self::assertContains(self::ADDED_DOMAIN_ENUM_CASE, $this->ignoredRegexes());
    }

    #[DataProvider('reportedLines')]
    public function test_the_policy_accepts_only_a_case_added_to_a_domain_enum(string $reportedLine, bool $accepted): void
    {
        self::assertSame($accepted, 1 === preg_match(self::ADDED_DOMAIN_ENUM_CASE, $reportedLine));
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function reportedLines(): iterable
    {
        yield 'a case added to a Domain enum' => [\sprintf('[BC] ADDED: Case %s::USE_CASE was added', ProjectFileType::class), true];
        yield 'a case removed from a Domain enum' => [\sprintf('[BC] REMOVED: Case %s::USE_CASE was removed', ProjectFileType::class), false];
        yield 'a case added to an enum outside the Domain models' => [\sprintf('[BC] ADDED: Case %s::PDF was added', OutputFormat::class), false];
        yield 'a case added to an enum in a namespace below the Domain models' => ['[BC] ADDED: Case VinceAmstoutz\\SymfonySecurityAuditor\\Audit\\Domain\\Model\\Report\\Format::PDF was added', false];
    }

    public function test_every_accepted_break_is_announced_under_unreleased(): void
    {
        $unannounced = [];
        foreach ($this->acceptedBreaks() as $pattern => $announcement) {
            if (null === $announcement || !UnreleasedChangelog::announces($announcement)) {
                $unannounced[] = $pattern;
            }
        }

        self::assertSame([], $unannounced, 'Put a <!-- CHANGELOG: "#123" --> comment naming the pull request that a bullet under ## [Unreleased] links right before each ignored-regex.');
    }

    public function test_every_accepted_break_is_one_reported_line(): void
    {
        $wildcards = array_values(array_filter(
            array_keys($this->acceptedBreaks()),
            static fn (string $pattern): bool => 1 !== preg_match(self::REPORTED_LINE, $pattern) || !self::isLiteral(substr($pattern, 1, -1)),
        ));

        self::assertSame([], $wildcards, 'An ignored-regex is the line the job reported, between # delimiters, with every metacharacter escaped.');
    }

    /**
     * @return list<string>
     */
    private function ignoredRegexes(): array
    {
        $domDocument = new DOMDocument();
        self::assertTrue($domDocument->load(self::BASELINE), 'The baseline is well-formed XML.');

        return array_map(static fn (DOMElement $domElement): string => $domElement->textContent, iterator_to_array($domDocument->getElementsByTagName('ignored-regex'), false));
    }

    /**
     * @return array<string, string|null> each accepted pattern, with the pull request its CHANGELOG comment names
     */
    private function acceptedBreaks(): array
    {
        $domDocument = new DOMDocument();
        self::assertTrue($domDocument->load(self::BASELINE), 'The baseline is well-formed XML.');

        $accepted = [];
        foreach ($domDocument->getElementsByTagName('ignored-regex') as $domNodeList) {
            if (self::ADDED_DOMAIN_ENUM_CASE !== $domNodeList->textContent) {
                $accepted[$domNodeList->textContent] = $this->announcement($domNodeList);
            }
        }

        return $accepted;
    }

    private function announcement(DOMElement $domElement): ?string
    {
        $previous = $domElement->previousSibling;
        while ($previous instanceof DOMText && '' === trim($previous->textContent)) {
            $previous = $previous->previousSibling;
        }

        return $previous instanceof DOMComment && 1 === preg_match(self::ANNOUNCEMENT, $previous->data, $match) ? $match[1] : null;
    }

    private static function isLiteral(string $body): bool
    {
        $escaped = false;
        foreach (str_split($body) as $character) {
            if (!self::isLiteralCharacter($character, $escaped)) {
                return false;
            }

            $escaped = !$escaped && '\\' === $character;
        }

        return !$escaped;
    }

    private static function isLiteralCharacter(string $character, bool $escaped): bool
    {
        return $escaped ? !ctype_alnum($character) : !str_contains(self::METACHARACTERS, $character);
    }
}
