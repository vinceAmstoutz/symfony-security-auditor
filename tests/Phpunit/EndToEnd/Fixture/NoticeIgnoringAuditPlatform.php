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
use Symfony\AI\Platform\PlainConverter;
use Symfony\AI\Platform\PlatformInterface;
use Symfony\AI\Platform\Result\DeferredResult;
use Symfony\AI\Platform\Result\InMemoryRawResult;
use Symfony\AI\Platform\Result\ToolCall;
use Symfony\AI\Platform\Result\ToolCallResult;
use Symfony\AI\Platform\Tool\Tool;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\FinalRound;

/**
 * Test double: answers like {@see ScriptedAuditPlatform}, except that the
 * attacker reads files past the notice that its next round is its last, and
 * only answers — recording what it found, or nothing — once its reading calls
 * came back unrun, on the closing request.
 */
final readonly class NoticeIgnoringAuditPlatform implements PlatformInterface
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
        if (!$this->isAttackerTurn($options) || !$input instanceof MessageBag) {
            return $this->scriptedAuditPlatform->invoke($model, $input, $options);
        }

        if ($this->wasRefusedItsReading($input)) {
            return $this->scriptedAuditPlatform->invoke($model, new MessageBag(...\array_slice($input->getMessages(), 0, 2)), $options);
        }

        return new DeferredResult(
            new PlainConverter(new ToolCallResult([new ToolCall('read-'.\count($input->getMessages()), 'read_file', ['path' => 'src/Controller/AdminController.php'])])),
            new InMemoryRawResult(['text' => ''], [], (object) []),
            $options,
        );
    }

    #[Override]
    public function getModelCatalog(): ModelCatalogInterface
    {
        return $this->scriptedAuditPlatform->getModelCatalog();
    }

    /**
     * @param array<string, mixed> $options
     */
    private function isAttackerTurn(array $options): bool
    {
        $tools = \is_array($options['tools'] ?? null) ? $options['tools'] : [];

        return [] !== array_filter($tools, static fn (mixed $tool): bool => $tool instanceof Tool && 'record_vulnerability' === $tool->getName());
    }

    private function wasRefusedItsReading(MessageBag $messageBag): bool
    {
        $messages = $messageBag->getMessages();
        $last = end($messages);

        return $last instanceof ToolCallMessage && FinalRound::NOT_RUN === $last->asText();
    }
}
