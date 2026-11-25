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

use Symfony\AI\Platform\Result\RawHttpResult;
use Symfony\AI\Platform\Result\RawResultInterface;
use Throwable;

/**
 * Reads the `usage` objects a raw answer reports: the one of an answer given
 * in one piece, or those of a streamed answer's events, in the order it sent
 * them. None when the answer cannot be read.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class ReportedUsages
{
    private const string EVENT_DATA_PREFIX = 'data:';

    /**
     * Returns the cache writes Anthropic keeps for an hour, as the last usage
     * that splits its writes reports them; zero when none does.
     */
    public static function oneHourCacheCreationTokens(RawResultInterface $rawResult): int
    {
        $oneHourCacheCreationTokens = 0;
        foreach (self::in($rawResult) as $usage) {
            $cacheCreation = \is_array($usage) ? $usage['cache_creation'] ?? null : null;
            $reportedTokens = \is_array($cacheCreation) ? $cacheCreation['ephemeral_1h_input_tokens'] ?? null : null;
            $oneHourCacheCreationTokens = \is_int($reportedTokens) ? $reportedTokens : $oneHourCacheCreationTokens;
        }

        return $oneHourCacheCreationTokens;
    }

    /**
     * @return list<mixed>
     */
    private static function in(RawResultInterface $rawResult): array
    {
        try {
            return [$rawResult->getData()['usage'] ?? null];
        } catch (Throwable) {
            return $rawResult instanceof RawHttpResult ? array_map(self::usageOf(...), self::streamedEvents($rawResult)) : [];
        }
    }

    /**
     * @return list<mixed>
     */
    private static function streamedEvents(RawHttpResult $rawHttpResult): array
    {
        try {
            $body = $rawHttpResult->getObject()->getContent();
        } catch (Throwable) {
            return [];
        }

        $events = [];
        foreach (explode("\n", $body) as $line) {
            if (str_starts_with($line, self::EVENT_DATA_PREFIX)) {
                $events[] = json_decode(substr($line, \strlen(self::EVENT_DATA_PREFIX)), true);
            }
        }

        return $events;
    }

    private static function usageOf(mixed $event): mixed
    {
        $message = \is_array($event) ? $event['message'] ?? null : null;

        return (\is_array($message) ? $message['usage'] ?? null : null) ?? (\is_array($event) ? $event['usage'] ?? null : null);
    }
}
