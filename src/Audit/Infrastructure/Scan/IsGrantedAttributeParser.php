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

use PhpParser\Node\Arg;
use PhpParser\Node\Attribute;
use PhpParser\Node\AttributeGroup;
use PhpParser\Node\Identifier;
use PhpParser\Node\Scalar\String_;

/**
 * Extracts `#[IsGranted(...)]`/`#[Security(...)]` attribute values —
 * `#[IsGranted]`'s value parameter is `$attribute`, `#[Security]`'s is
 * `$expression`; both are resolved the same way, matched by name when the
 * call uses named arguments (so a reordered call still yields the right
 * argument) or by position otherwise.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class IsGrantedAttributeParser
{
    /**
     * @param array<AttributeGroup> $attributeGroups
     *
     * @return list<string>
     */
    public function extractValues(array $attributeGroups): array
    {
        $values = [];
        foreach ($attributeGroups as $attributeGroup) {
            foreach ($this->valuesFromAttributes($attributeGroup->attrs) as $value) {
                $values[] = $value;
            }
        }

        return $values;
    }

    /**
     * A value argument is a genuine access check even when it cannot be
     * resolved to a literal string (an enum case, `new Expression(...)`) —
     * presence alone is sufficient, matching this parser's established
     * "presence is sufficient" heuristic. Only {@see self::extractValues()}'s
     * display list is limited to literal strings.
     *
     * @param array<AttributeGroup> $attributeGroups
     */
    public function hasValueArg(array $attributeGroups): bool
    {
        foreach ($attributeGroups as $attributeGroup) {
            if ($this->hasValueArgInAttributes($attributeGroup->attrs)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param array<Attribute> $attributes
     *
     * @return list<string>
     */
    private function valuesFromAttributes(array $attributes): array
    {
        $values = [];
        foreach ($attributes as $attribute) {
            $valueArgName = $this->valueArgNameFor($attribute->name->toString());
            if (null === $valueArgName) {
                continue;
            }

            $attributeArg = $this->attributeArgValue($attribute->args, $valueArgName);
            if (null !== $attributeArg) {
                $values[] = $attributeArg;
            }
        }

        return $values;
    }

    /**
     * @param array<Attribute> $attributes
     */
    private function hasValueArgInAttributes(array $attributes): bool
    {
        foreach ($attributes as $attribute) {
            $valueArgName = $this->valueArgNameFor($attribute->name->toString());
            if (null !== $valueArgName && $this->attributeHasMatchingArg($attribute->args, $valueArgName)) {
                return true;
            }
        }

        return false;
    }

    private function valueArgNameFor(string $shortName): ?string
    {
        return match (true) {
            $this->attributeShortNameMatches($shortName, 'IsGranted') => 'attribute',
            $this->attributeShortNameMatches($shortName, 'Security') => 'expression',
            default => null,
        };
    }

    /**
     * @param list<Arg> $args
     */
    private function attributeArgValue(array $args, string $valueArgName): ?string
    {
        foreach ($args as $index => $arg) {
            if (!$arg->value instanceof String_) {
                continue;
            }

            if ($this->isMatchingArg($arg, $index, $valueArgName)) {
                return $arg->value->value;
            }
        }

        return null;
    }

    /**
     * @param list<Arg> $args
     */
    private function attributeHasMatchingArg(array $args, string $valueArgName): bool
    {
        foreach ($args as $index => $arg) {
            if ($this->isMatchingArg($arg, $index, $valueArgName)) {
                return true;
            }
        }

        return false;
    }

    private function isMatchingArg(Arg $arg, int $index, string $valueArgName): bool
    {
        return match (true) {
            $arg->name instanceof Identifier => $valueArgName === $arg->name->toString(),
            default => 0 === $index,
        };
    }

    private function attributeShortNameMatches(string $fullyQualifiedName, string $expectedShortName): bool
    {
        $parts = explode('\\', $fullyQualifiedName);

        return end($parts) === $expectedShortName;
    }
}
