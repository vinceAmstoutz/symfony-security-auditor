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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception;

use RuntimeException;
use Symfony\Component\Yaml\Exception\ParseException;

/** @internal not part of the BC promise — see docs/versioning.md */
final class MalformedProjectConfigException extends RuntimeException
{
    public static function fromParseException(string $configFile, ParseException $parseException): self
    {
        return new self(\sprintf('Config file "%s" is not valid YAML: %s', $configFile, $parseException->getMessage()), previous: $parseException);
    }
}
