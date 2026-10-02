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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tooling\PHPUnit;

use SimpleXMLElement;

/**
 * The statements a Clover report records as never executed, so a failed
 * coverage gate can name what is missing instead of only a percentage — the
 * difference between a one-line diagnosis and a bisect.
 */
final readonly class UncoveredLines
{
    private const string UNCOVERED_STATEMENTS = 'line[@type="stmt"][@count="0"]';

    /**
     * @return list<string> `path:line`, in report order
     */
    public static function in(string $cloverReport): array
    {
        $document = self::parse($cloverReport);
        if (!$document instanceof SimpleXMLElement) {
            return [];
        }

        $uncovered = [];
        foreach (self::query($document, '//file') as $file) {
            foreach (self::query($file, self::UNCOVERED_STATEMENTS) as $line) {
                $uncovered[] = \sprintf('%s:%s', (string) $file['name'], (string) $line['num']);
            }
        }

        return $uncovered;
    }

    private static function parse(string $cloverReport): ?SimpleXMLElement
    {
        $previous = libxml_use_internal_errors(true);
        $document = simplexml_load_string($cloverReport);
        libxml_clear_errors();
        libxml_use_internal_errors($previous);

        return false !== $document ? $document : null;
    }

    /**
     * @return list<SimpleXMLElement>
     */
    private static function query(SimpleXMLElement $element, string $expression): array
    {
        $matches = $element->xpath($expression);

        return \is_array($matches) ? array_values($matches) : [];
    }
}
