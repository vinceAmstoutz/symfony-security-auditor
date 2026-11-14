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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Fixture\Bridge;

use Generator;
use Symfony\AI\Platform\FinishReason\FinishReason;
use Symfony\AI\Platform\FinishReason\FinishReasonCase;
use Symfony\AI\Platform\Model;
use Symfony\AI\Platform\PlatformInterface;
use Symfony\AI\Platform\Result\ResultInterface;
use Symfony\AI\Platform\Result\Stream\Delta\MetadataDelta;
use Symfony\AI\Platform\Result\Stream\Delta\TextDelta;
use Symfony\AI\Platform\Result\StreamResult;
use Symfony\AI\Platform\Test\MockPlatformFactory;
use Symfony\AI\Platform\TokenUsage\TokenUsage;

/**
 * A stub bridge's platform: one fixed answer, streamed with its usage and
 * finish reason when the call asks for a stream, as a real bridge does.
 */
final readonly class StubAnswerPlatform
{
    public static function answering(string $answer): PlatformInterface
    {
        return MockPlatformFactory::createPlatform(static fn (Model $model, array|string|object $input, array $options): ResultInterface|string => true === ($options['stream'] ?? false) ? self::streamed($answer) : $answer);
    }

    private static function streamed(string $answer): StreamResult
    {
        return new StreamResult((static function () use ($answer): Generator {
            yield new TextDelta($answer);
            yield new TokenUsage(promptTokens: 0, completionTokens: 0);
            yield new MetadataDelta('finish_reason', new FinishReason(FinishReasonCase::STOP, 'stop'));
        })());
    }
}
