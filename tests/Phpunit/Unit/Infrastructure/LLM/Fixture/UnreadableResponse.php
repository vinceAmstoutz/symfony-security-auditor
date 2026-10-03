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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\LLM\Fixture;

use Override;
use Symfony\Component\HttpClient\Exception\TransportException;
use Symfony\Contracts\HttpClient\ResponseInterface;

/**
 * Test fake: an HTTP response whose connection was cut before anything could
 * be read from it, so every read fails the way symfony/http-client fails it.
 */
final readonly class UnreadableResponse implements ResponseInterface
{
    #[Override]
    public function getStatusCode(): int
    {
        throw $this->connectionCut();
    }

    /**
     * @return array<string, list<string>>
     */
    #[Override]
    public function getHeaders(bool $throw = true): array
    {
        throw $this->connectionCut();
    }

    #[Override]
    public function getContent(bool $throw = true): string
    {
        throw $this->connectionCut();
    }

    /**
     * @return array<array-key, mixed>
     */
    #[Override]
    public function toArray(bool $throw = true): array
    {
        throw $this->connectionCut();
    }

    #[Override]
    public function cancel(): void {}

    #[Override]
    public function getInfo(?string $type = null): mixed
    {
        return null;
    }

    private function connectionCut(): TransportException
    {
        return new TransportException('Transfer closed with 512 bytes remaining to read for "https://gw.example.com/v1/chat/completions".');
    }
}
