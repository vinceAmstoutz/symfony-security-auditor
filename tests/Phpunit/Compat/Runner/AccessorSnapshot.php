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

use DateTimeInterface;
use ReflectionMethod;
use ReflectionObject;
use Throwable;
use UnitEnum;

/**
 * What a Domain object answers through its public accessors — every public,
 * non-static method that takes no argument and does not change the object —
 * nested a few levels deep. A method that throws is kept as the exception's
 * class and message.
 */
final readonly class AccessorSnapshot
{
    private const string DOMAIN_NAMESPACE = 'VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\\';

    private const array MUTATOR_PREFIXES = ['with', 'set', 'add', 'replace', 'remove', 'mark', 'record', 'clear', 'drain', 'merge', 'increment', '__'];

    private const int MAX_ITEMS = 50;

    public static function of(mixed $value, int $depth): mixed
    {
        return match (true) {
            $value instanceof UnitEnum => \sprintf('%s::%s', self::shortName($value), $value->name),
            $value instanceof DateTimeInterface => '<TIMESTAMP>',
            \is_object($value) => self::accessorsOf($value, $depth),
            \is_array($value) => array_map(static fn (mixed $item): mixed => self::of($item, $depth), \array_slice($value, 0, self::MAX_ITEMS, true)),
            \is_float($value) => round($value, 6),
            default => $value,
        };
    }

    /**
     * @return array<string, mixed>
     */
    public static function accessorsOf(object $object, int $depth): array
    {
        if ($depth <= 0 || !str_starts_with($object::class, self::DOMAIN_NAMESPACE)) {
            return ['@class' => $object::class];
        }

        $snapshot = ['@class' => $object::class];
        foreach (self::accessors($object) as $reflectionMethod) {
            $snapshot[\sprintf('%s()', $reflectionMethod->getName())] = self::called($reflectionMethod, $object, $depth - 1);
        }

        return $snapshot;
    }

    private static function called(ReflectionMethod $reflectionMethod, object $object, int $depth): mixed
    {
        try {
            return self::of($reflectionMethod->invoke($object), $depth);
        } catch (Throwable $throwable) {
            return \sprintf('!%s: %s', $throwable::class, $throwable->getMessage());
        }
    }

    /**
     * @return list<ReflectionMethod>
     */
    private static function accessors(object $object): array
    {
        $accessors = array_filter(
            (new ReflectionObject($object))->getMethods(ReflectionMethod::IS_PUBLIC),
            static fn (ReflectionMethod $reflectionMethod): bool => !$reflectionMethod->isStatic()
                && 0 === $reflectionMethod->getNumberOfRequiredParameters()
                && !self::isMutator($reflectionMethod->getName()),
        );
        usort($accessors, static fn (ReflectionMethod $left, ReflectionMethod $right): int => strcmp($left->getName(), $right->getName()));

        return $accessors;
    }

    private static function isMutator(string $method): bool
    {
        foreach (self::MUTATOR_PREFIXES as $prefix) {
            if (str_starts_with($method, $prefix)) {
                return true;
            }
        }

        return false;
    }

    private static function shortName(object $object): string
    {
        $position = strrpos($object::class, '\\');

        return false === $position ? $object::class : substr($object::class, $position + 1);
    }
}
