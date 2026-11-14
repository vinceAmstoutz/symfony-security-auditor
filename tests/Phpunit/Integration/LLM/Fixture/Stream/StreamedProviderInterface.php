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

use Symfony\AI\Platform\PlatformInterface;
use Symfony\Component\HttpClient\Response\MockResponse;

/**
 * A provider's real symfony/ai platform and the stream it answers with, in
 * that provider's own wire format.
 */
interface StreamedProviderInterface
{
    public function servingPlatform(): string;

    public function model(): string;

    public function platform(MockResponse ...$answers): PlatformInterface;

    public function textAnswer(string $text, int $inputTokens, int $outputTokens): MockResponse;

    /**
     * @param array<string, mixed> $arguments
     */
    public function toolCallAnswer(string $tool, array $arguments): MockResponse;

    public function askedForAStream(MockResponse $answer): bool;
}
