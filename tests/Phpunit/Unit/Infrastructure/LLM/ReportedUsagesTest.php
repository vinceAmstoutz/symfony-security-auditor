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
use Symfony\AI\Platform\Result\RawHttpResult;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\ReportedUsages;

final class ReportedUsagesTest extends TestCase
{
    public function test_it_reads_the_one_hour_cache_writes_the_last_event_of_a_stream_that_splits_them_reports(): void
    {
        $body = implode('', array_map(static fn (array $event): string => \sprintf("event: %s\ndata: %s\n\n", $event['type'], json_encode($event, \JSON_THROW_ON_ERROR)), [
            ['type' => 'message_start', 'message' => ['usage' => ['input_tokens' => 12, 'cache_creation_input_tokens' => 500]]],
            ['type' => 'message_delta', 'usage' => ['output_tokens' => 9, 'cache_creation' => ['ephemeral_5m_input_tokens' => 100, 'ephemeral_1h_input_tokens' => 400]]],
            ['type' => 'message_stop'],
        ]));
        $response = (new MockHttpClient([new MockResponse($body, ['response_headers' => ['content-type' => 'text/event-stream']])]))->request('POST', 'https://api.example.com/v1/messages');

        self::assertSame(400, ReportedUsages::oneHourCacheCreationTokens(new RawHttpResult($response)));
    }
}
