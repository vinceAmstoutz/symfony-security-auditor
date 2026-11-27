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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM;

use Closure;
use Symfony\AI\Platform\Result\DeferredResult;

/**
 * The streamed call sent again without streaming, at most once, when the
 * platform hands back unread a successful answer given in one piece, as a
 * platform a debug kernel traces does.
 *
 * Not `readonly`: it keeps the call it sent (`.claude/rules/php-classes.md`).
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final class BufferedResend
{
    private ?DeferredResult $resentResult = null;

    /**
     * @param Closure(): DeferredResult $bufferedCall
     */
    public function __construct(private readonly Closure $bufferedCall) {}

    public function resent(): DeferredResult
    {
        return $this->resentResult ??= ($this->bufferedCall)();
    }

    /**
     * Returns the call that answered: the one sent again, if it was.
     */
    public function answering(DeferredResult $streamedResult): DeferredResult
    {
        return $this->resentResult ?? $streamedResult;
    }
}
