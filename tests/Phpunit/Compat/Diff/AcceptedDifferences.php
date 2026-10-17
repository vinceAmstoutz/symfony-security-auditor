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

use UnexpectedValueException;

/**
 * The differences against the recorded release the maintainer accepted, read
 * from `tests/Phpunit/Compat/accepted-differences.php`.
 */
final readonly class AcceptedDifferences
{
    private const string FILE = __DIR__.'/../accepted-differences.php';

    /**
     * @return list<AcceptedDifference>
     */
    public static function all(): array
    {
        $entries = require self::FILE;
        if (!\is_array($entries) || !array_is_list($entries)) {
            throw new UnexpectedValueException('accepted-differences.php returns a list of entries.');
        }

        return array_map(
            static fn (mixed $entry): AcceptedDifference => \is_array($entry) ? AcceptedDifference::fromArray($entry) : throw new UnexpectedValueException('Each accepted difference is an array.'),
            $entries,
        );
    }

    /**
     * @return list<AcceptedDifference>
     */
    public static function forScenario(string $scenario): array
    {
        return array_values(array_filter(self::all(), static fn (AcceptedDifference $acceptedDifference): bool => $acceptedDifference->appliesTo($scenario)));
    }
}
