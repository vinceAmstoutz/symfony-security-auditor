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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\LLM;

use PHPUnit\Framework\TestCase;
use Symfony\AI\Platform\PlainConverter;
use Symfony\AI\Platform\Result\DeferredResult;
use Symfony\AI\Platform\Result\InMemoryRawResult;
use Symfony\AI\Platform\Result\TextResult;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\BufferedResend;

final class BufferedResendTest extends TestCase
{
    public function test_it_sends_the_call_again_once_however_often_it_is_asked(): void
    {
        $sent = 0;
        $bufferedResend = new BufferedResend(static function () use (&$sent): DeferredResult {
            ++$sent;

            return new DeferredResult(new PlainConverter(new TextResult('answer')), new InMemoryRawResult());
        });

        $bufferedResend->resent();
        $bufferedResend->resent();

        self::assertSame(1, $sent);
    }
}
