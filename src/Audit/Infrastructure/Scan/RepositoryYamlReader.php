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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan;

use Symfony\Component\Yaml\Yaml;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\Exception\UnreadableYamlException;

/**
 * Parses YAML the audited repository supplies, with its custom tags such as
 * `!tagged_iterator`, as the Symfony kernel does. Symfony YAML copies the
 * rest of a block-style document at every level it descends, so a file is
 * refused before the parse when its size or its nesting could exhaust the
 * memory of the run, and any failure of the parse refuses the file instead
 * of ending the run.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class RepositoryYamlReader
{
    private const int MAX_BYTES = 262_144;

    private const int MAX_NESTING_DEPTH = 32;

    /**
     * @return array<mixed> the document, or an empty map for a document that is not a collection
     *
     * @throws UnreadableYamlException
     */
    public function read(string $content): array
    {
        if (self::MAX_BYTES < \strlen($content)) {
            throw UnreadableYamlException::tooLarge(\strlen($content), self::MAX_BYTES);
        }

        $this->assertNestedWithinLimit($content);

        try {
            $document = Yaml::parse($content, Yaml::PARSE_CUSTOM_TAGS);
        } catch (Throwable $throwable) {
            throw UnreadableYamlException::unparseable($throwable);
        }

        return \is_array($document) ? $document : [];
    }

    /**
     * Counts the blocks open at each line, whatever width each level is
     * indented by; blank and comment lines open none.
     *
     * @throws UnreadableYamlException
     */
    private function assertNestedWithinLimit(string $content): void
    {
        $openIndents = [];
        foreach (explode("\n", $content) as $line) {
            $text = ltrim($line, ' ');
            if ($this->opensNoBlock($text)) {
                continue;
            }

            $openIndents = $this->closedBefore(\strlen($line) - \strlen($text), $openIndents);
            if (self::MAX_NESTING_DEPTH < \count($openIndents)) {
                throw UnreadableYamlException::nestedTooDeep(self::MAX_NESTING_DEPTH);
            }
        }
    }

    private function opensNoBlock(string $text): bool
    {
        return '' === trim($text) || str_starts_with($text, '#');
    }

    /**
     * The open blocks are indented further at each level, so those a line of
     * this indent leaves open are the ones indented less than it.
     *
     * @param list<int> $openIndents
     *
     * @return list<int> the blocks still open at a line of this indent, that line's own last
     */
    private function closedBefore(int $indent, array $openIndents): array
    {
        return [...array_filter($openIndents, static fn (int $openIndent): bool => $openIndent < $indent), $indent];
    }
}
