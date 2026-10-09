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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Scan;

use Symfony\Component\String\AbstractString;

use function Symfony\Component\String\b;
use function Symfony\Component\String\u;

/**
 * A path typed on the command line is bytes: a Latin-1 directory name is not
 * valid UTF-8, and `u()` refuses it. Text that is valid UTF-8 is handled as
 * Unicode, as it always was; any other is handled byte for byte, so it reaches
 * the filesystem exactly as typed.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class PathText
{
    public static function of(string $path): AbstractString
    {
        return mb_check_encoding($path, 'UTF-8') ? u($path) : b($path);
    }
}
