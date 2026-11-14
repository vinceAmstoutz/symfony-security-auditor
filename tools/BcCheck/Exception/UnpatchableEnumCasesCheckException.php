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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tooling\BcCheck\Exception;

use RuntimeException;

final class UnpatchableEnumCasesCheckException extends RuntimeException
{
    public static function forUnreadableCheck(string $path): self
    {
        return new self(\sprintf('The enum cases check of roave/backward-compatibility-check could not be read at "%s": install tools/bc-check first.', $path));
    }

    public static function forUnknownReport(string $expected): self
    {
        return new self(\sprintf('The enum cases check of roave/backward-compatibility-check does not return its added enum cases the way this install expects (one "%s" line): update tools/BcCheck/RoaveEnumCaseAdditions.php for this Roave release.', $expected));
    }
}
