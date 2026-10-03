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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\EndToEnd\Fixture;

use Override;
use Symfony\AI\Platform\Message\MessageBag;
use Symfony\AI\Platform\Message\ToolCallMessage;
use Symfony\AI\Platform\Model;
use Symfony\AI\Platform\ModelCatalog\ModelCatalogInterface;
use Symfony\AI\Platform\PlatformInterface;
use Symfony\AI\Platform\Result\DeferredResult;
use Symfony\AI\Platform\Tool\Tool;
use Symfony\Component\HttpClient\Exception\TransportException;

/**
 * Test double: answers like {@see ScriptedAuditPlatform}, except that once the
 * attacker's conversation has run a tool, every later attacker call loses its
 * connection mid-response, the way a gateway dropping idle sockets does.
 */
final readonly class ConnectionCutAfterToolAuditPlatform implements PlatformInterface
{
    private ScriptedAuditPlatform $scriptedAuditPlatform;

    public function __construct()
    {
        $this->scriptedAuditPlatform = new ScriptedAuditPlatform();
    }

    /**
     * @param array<array-key, mixed>|string|object $input
     * @param array<string, mixed>                  $options
     */
    #[Override]
    public function invoke(Model|string $model, array|string|object $input, array $options = []): DeferredResult
    {
        if ($this->isAttackerTurnAfterAToolRan($input, $options)) {
            throw new TransportException('OpenSSL SSL_read: SSL_ERROR_SYSCALL, errno 0 for "https://llm.example/v1/chat/completions".');
        }

        return $this->scriptedAuditPlatform->invoke($model, $input, $options);
    }

    #[Override]
    public function getModelCatalog(): ModelCatalogInterface
    {
        return $this->scriptedAuditPlatform->getModelCatalog();
    }

    /**
     * @param array<array-key, mixed>|string|object $input
     * @param array<string, mixed>                  $options
     */
    private function isAttackerTurnAfterAToolRan(array|string|object $input, array $options): bool
    {
        $tools = \is_array($options['tools'] ?? null) ? $options['tools'] : [];
        $attackerTurn = [] !== array_filter($tools, static fn (mixed $tool): bool => $tool instanceof Tool && 'record_vulnerability' === $tool->getName());

        return $attackerTurn && $input instanceof MessageBag && [] !== array_filter($input->getMessages(), static fn (object $message): bool => $message instanceof ToolCallMessage);
    }
}
