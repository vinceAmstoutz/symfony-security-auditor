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
final class ConflictingCommandOptionsException extends InvalidArgumentException
{
    public static function forGenerateBaselineWithPreviewFlag(string $previewFlag): self
    {
        return new self(\sprintf(
            '--generate-baseline requires a real audit run and cannot be combined with %s, which exits before the LLM is ever invoked.',
            $previewFlag,
        ));
    }
}
