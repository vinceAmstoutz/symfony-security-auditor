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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception;

/**
 * A prompt holding one small file was refused: its fixed part (the system
 * prompt and the project mapping) leaves no room in the model's context window
 * or the input-token rate limit. No split helps, so the audit stops.
 */
final class LLMFixedPromptTooLargeException extends LLMProviderException
{
    public static function forFile(string $filePath, int $bytes, string $reason): self
    {
        return new self(\sprintf(
            'The audit prompt was refused even with only the %d-byte file "%s" in it (%s): the system prompt and the project mapping around it take up the rest, so no file can fit. Use a model with a larger context window for the attacker, raise audit.rate_limit.input_tokens_per_minute when that limit refused it, or narrow scan.included_paths.',
            $bytes,
            $filePath,
            $reason,
        ));
    }
}
