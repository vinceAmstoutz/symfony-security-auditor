<?php

declare(strict_types=1);

namespace App\Messenger;

use App\Message\GitHubWebhookReceived;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;

// INTENTIONALLY VULNERABLE — for demonstrating symfony-security-auditor.
// Do not deploy. Do not copy any of this into a real codebase.
#[AsMessageHandler]
final class GitHubWebhookHandler
{
    // VULN: missing webhook signature verification / no replay protection — the
    // handler acts on the payload without ever checking the `X-Hub-Signature`
    // HMAC or de-duplicating the delivery id, so anyone who learns the endpoint
    // can forge or replay a deploy event. A real fix verifies the signature with
    // `hash_equals()` and records the delivery id to reject replays.
    public function __invoke(GitHubWebhookReceived $message): void
    {
        if ('push' === $message->event) {
            $this->triggerDeploy($message->repository);
        }
    }

    private function triggerDeploy(string $repository): void
    {
        // deploy $repository …
    }
}
