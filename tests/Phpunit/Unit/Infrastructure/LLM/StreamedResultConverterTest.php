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
use Symfony\AI\Platform\Model;
use Symfony\AI\Platform\PlainConverter;
use Symfony\AI\Platform\Result\DeferredResult;
use Symfony\AI\Platform\Result\InMemoryRawResult;
use Symfony\AI\Platform\Result\TextResult;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\StreamedResultConverter;

final class StreamedResultConverterTest extends TestCase
{
    public function test_it_reads_the_streamed_answer_of_whichever_model_produced_it(): void
    {
        $streamedResultConverter = new StreamedResultConverter(new DeferredResult(new PlainConverter(new TextResult('')), new InMemoryRawResult()));

        self::assertTrue($streamedResultConverter->supports(new Model('any-model')));
    }
}
