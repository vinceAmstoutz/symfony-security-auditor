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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\Stream;

use Symfony\Component\HttpClient\Response\MockResponse;

final readonly class ServerSentEvents
{
    /**
     * @param array<string, mixed> ...$events
     */
    public static function of(array ...$events): MockResponse
    {
        $body = '';
        foreach ($events as $event) {
            $body .= \sprintf("data: %s\n\n", json_encode($event, \JSON_THROW_ON_ERROR));
        }

        return new MockResponse($body, ['response_headers' => ['content-type' => 'text/event-stream']]);
    }

    /**
     * @param array<string, mixed> ...$events
     */
    public static function withDone(array ...$events): MockResponse
    {
        $body = '';
        foreach ($events as $event) {
            $body .= \sprintf("data: %s\n\n", json_encode($event, \JSON_THROW_ON_ERROR));
        }

        return new MockResponse($body."data: [DONE]\n\n", ['response_headers' => ['content-type' => 'text/event-stream']]);
    }
}
