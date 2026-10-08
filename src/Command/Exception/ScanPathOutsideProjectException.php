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

namespace VinceAmstoutz\SymfonySecurityAuditor\Command\Exception;

use InvalidArgumentException;

/** @internal not part of the BC promise — see docs/versioning.md */
final class ScanPathOutsideProjectException extends InvalidArgumentException
{
    public static function forPath(string $scanPath, string $projectPath): self
    {
        return new self(\sprintf('The --path "%s" lies outside the project "%s". Give --path relative to the project root, for example --path src/Controller.', $scanPath, $projectPath));
    }
}
