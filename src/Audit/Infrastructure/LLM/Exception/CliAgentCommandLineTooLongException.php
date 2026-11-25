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

use RuntimeException;

/**
 * A request no split can make fit: the system prompt alone outgrows the
 * command line a CLI agent is started with.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final class CliAgentCommandLineTooLongException extends RuntimeException
{
    public static function onWindows(int $longestCommandLine, int $systemPromptBytes): self
    {
        return new self(\sprintf(
            "On Windows, the command line that starts the CLI of a Claude or ChatGPT subscription holds at most %d characters, but the auditor's instructions alone take %d bytes, so the audit cannot run on a subscription there. Run it under WSL, on Linux or macOS, or on an API platform.",
            $longestCommandLine,
            $systemPromptBytes,
        ));
    }
}
