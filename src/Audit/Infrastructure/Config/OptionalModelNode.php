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
use Symfony\Component\Config\Definition\NodeInterface;
use Symfony\Component\Config\Definition\ScalarNode;

/**
 * A model id that may be left out or set to null, never to an empty string.
 * Symfony checks an `%env()%` placeholder against a node with an empty stand-in
 * value when its variable declares no default, so a validation closure would
 * refuse every placeholder; this node refuses only an empty string written as
 * such, as `cannotBeEmpty()` does for `model`.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final class OptionalModelNode extends ScalarNode
{
    public function __construct(?string $name, ?NodeInterface $parent, string $pathSeparator, private readonly string $emptyStringError)
    {
        parent::__construct($name, $parent, $pathSeparator);
    }

    /**
     * @throws InvalidConfigurationException
     */
    #[Override]
    protected function finalizeValue(mixed $value): mixed
    {
        if ('' === $value && !$this->isHandlingPlaceholder()) {
            throw new InvalidConfigurationException(\sprintf('Invalid configuration for path "%s": %s', $this->getPath(), $this->emptyStringError));
        }

        return parent::finalizeValue($value);
    }
}
