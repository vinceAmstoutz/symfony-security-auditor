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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunk;

use Throwable;

use function Symfony\Component\String\u;

/**
 * Names, for a person reading the progress output, why a chunk ended errored.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ChunkFailureReason
{
    public const string NOT_JSON = 'the answer was not valid JSON';

    public const string FILE_TOO_LARGE = 'the file is too large for the model input limit';

    private const int MAX_MESSAGE_LENGTH = 120;

    public static function fromStopReason(string $stopReason): string
    {
        return match ($stopReason) {
            'max_tool_iterations' => 'tool-call limit reached (audit.max_tool_iterations)',
            'length' => 'output token limit reached (max_output_tokens)',
            'content-filter' => 'answer withheld by the provider content filter',
            'empty_content' => 'the model returned no content',
            default => \sprintf('answer cut short (%s)', $stopReason),
        };
    }

    public static function fromThrowable(Throwable $throwable): string
    {
        $message = u($throwable->getMessage())->collapseWhitespace()->truncate(self::MAX_MESSAGE_LENGTH, '…')->toString();

        return '' === $message ? $throwable::class : $message;
    }
}
