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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Mcp;

use Mcp\Server\Transport\BaseTransport;
use Override;

/**
 * An MCP client that sends a fixed list of requests to `mcp:serve`, one at a
 * time, and keeps every message the server sends back, in order, in a JSON
 * file: the replies the server queues for the session are read after each
 * request, as the stdio transport does between two lines of input.
 *
 * @extends BaseTransport<null>
 */
final class CapturingMcpTransport extends BaseTransport
{
    /** @var list<mixed> */
    private array $received = [];

    /**
     * @param list<string> $requests
     */
    public function __construct(
        private readonly array $requests,
        private readonly string $output,
    ) {
        parent::__construct();
    }

    /**
     * @param array<string, mixed> $context
     */
    #[Override]
    public function send(string $data, array $context): void
    {
        $this->keep($data);
    }

    #[Override]
    public function listen(): mixed
    {
        foreach ($this->requests as $request) {
            $this->handleMessage($request, $this->sessionId);
            foreach ($this->getOutgoingMessages($this->sessionId) as $outgoing) {
                $this->keep($outgoing['message']);
            }
        }

        $this->handleSessionEnd($this->sessionId);

        return null;
    }

    private function keep(string $message): void
    {
        $this->received[] = json_decode($message, true);
        file_put_contents($this->output, (string) json_encode($this->received, \JSON_PRETTY_PRINT | \JSON_UNESCAPED_SLASHES));
    }
}
