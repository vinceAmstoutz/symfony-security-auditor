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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception;

use Symfony\AI\Platform\Exception\ExceedContextSizeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\CommandLineLimitExceptionInterface;

/**
 * A prompt longer than the command line a CLI agent is started with can
 * carry, which a smaller request may fit.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final class CliAgentPromptTooLongException extends ExceedContextSizeException implements CommandLineLimitExceptionInterface
{
    public static function forOneArgument(int $longestArgument): self
    {
        return new self(\sprintf('The prompt is longer than the %d bytes one command-line argument of the CLI can carry.', $longestArgument));
    }

    public static function forTheWindowsCommandLine(int $promptRoom): self
    {
        return new self(\sprintf('The prompt is longer than the %d bytes the Windows command line of the CLI leaves it.', $promptRoom));
    }
}
