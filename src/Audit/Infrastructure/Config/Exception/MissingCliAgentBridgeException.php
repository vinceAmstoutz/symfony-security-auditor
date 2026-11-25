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

/**
 * Words the refusal as `symfony/ai-bundle` words a missing platform bridge, so
 * the standalone binary turns it into the same `init` advice.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final class MissingCliAgentBridgeException extends RuntimeException
{
    public static function forCliAgent(string $cliAgent, string $package): self
    {
        return new self(\sprintf('The "%s" CLI agent requires "%s" package. Try running "composer require %2$s".', $cliAgent, $package));
    }
}
