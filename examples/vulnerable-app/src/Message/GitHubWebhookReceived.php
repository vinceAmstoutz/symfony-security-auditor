<?php

declare(strict_types=1);

namespace App\Message;

// INTENTIONALLY VULNERABLE FIXTURE — for demonstrating symfony-security-auditor.
// Do not deploy. Do not copy any of this into a real codebase.
final readonly class GitHubWebhookReceived
{
    public function __construct(
        public string $event,
        public string $repository,
        public string $deliveryId,
    ) {}
}
