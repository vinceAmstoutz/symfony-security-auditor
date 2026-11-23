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
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\Config\Definition\Exception\InvalidTypeException;
use Symfony\Component\Config\Definition\NodeInterface;
use Symfony\Component\Config\Definition\ScalarNode;

/**
 * A model id: refuses a number or a switch written as such, takes any
 * `%env()%` placeholder. Given an empty-string error it is a model override,
 * which may be left out or null but not empty; given none it is `model`,
 * which may be neither.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final class OptionalModelNode extends ScalarNode
{
    public function __construct(?string $name, ?NodeInterface $parent, string $pathSeparator, private readonly ?string $emptyStringError)
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

        if (null !== $value && !\is_string($value) && !$this->isHandlingPlaceholder()) {
            throw new InvalidTypeException(\sprintf('Invalid type for path "%s". Expected "string", but got "%s".', $this->getPath(), get_debug_type($value)));
        }
    }

    /**
     * @throws InvalidConfigurationException
     */
    #[Override]
    protected function finalizeValue(mixed $value): mixed
    {
        if ('' === $value && null !== $this->emptyStringError && !$this->isHandlingPlaceholder()) {
            throw new InvalidConfigurationException(\sprintf('Invalid configuration for path "%s": %s', $this->getPath(), $this->emptyStringError));
        }

        return parent::finalizeValue($value);
    }
}
