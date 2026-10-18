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

use Override;
use Symfony\Component\Config\Definition\Exception\InvalidTypeException;
use Symfony\Component\Config\Definition\NodeInterface;
use Symfony\Component\Config\Definition\ScalarNode;

/**
 * A setting that holds text — a path, a folder, a skill's instructions: a
 * string, or null where it may be left unset, never a number or a switch
 * written as such, which the typed configuration would otherwise reject with
 * a raw `TypeError`. Symfony checks an `%env()%` placeholder against a
 * stand-in value — empty or null after its variable's default, typed after its
 * processor — so a placeholder is taken whatever its stand-in, as before.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final class TextNode extends ScalarNode
{
    public function __construct(?string $name, ?NodeInterface $parent, string $pathSeparator, private readonly bool $nullable)
    {
        parent::__construct($name, $parent, $pathSeparator);
    }

    /**
     * @throws InvalidTypeException
     */
    #[Override]
    protected function validateType(mixed $value): void
    {
        parent::validateType($value);

        if (!\is_string($value) && !$this->isUnset($value) && !$this->isHandlingPlaceholder()) {
            throw new InvalidTypeException(\sprintf('Invalid type for path "%s". Expected "string", but got "%s".', $this->getPath(), get_debug_type($value)));
        }
    }

    private function isUnset(mixed $value): bool
    {
        return $this->nullable && null === $value;
    }
}
