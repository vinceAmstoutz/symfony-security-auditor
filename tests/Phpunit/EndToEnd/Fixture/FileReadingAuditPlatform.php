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

/**
 * Test double: answers like {@see ScriptedAuditPlatform}, except that every
 * conversation offered the `read_file` tool first reads {@see self::READ_PATH}
 * and keeps the tool's answer in {@see self::$answers}, keyed by the agent that
 * asked (`attacker` or `reviewer`), before it answers as the scripted platform does.
 */
final class FileReadingAuditPlatform implements PlatformInterface
{
    public const string READ_PATH = 'src/Service/Clean.php';

    /** @var array<string, string> */
    public static array $answers = [];

    private readonly ScriptedAuditPlatform $scriptedAuditPlatform;

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
        $toolNames = $this->toolNames($options);

        if (!$input instanceof MessageBag || !\in_array('read_file', $toolNames, true)) {
            return $this->scriptedAuditPlatform->invoke($model, $input, $options);
        }

        $toolAnswers = $this->toolAnswers($input);

        if ([] === $toolAnswers) {
            return new DeferredResult(
                new PlainConverter(new ToolCallResult([new ToolCall('read', 'read_file', ['relative_path' => self::READ_PATH])])),
                new InMemoryRawResult(['text' => ''], [], (object) []),
                $options,
            );
        }

        if (1 < \count($toolAnswers)) {
            return $this->scriptedAuditPlatform->invoke($model, $input, $options);
        }

        self::$answers[\in_array('record_vulnerability', $toolNames, true) ? 'attacker' : 'reviewer'] = $toolAnswers[0];

        return $this->scriptedAuditPlatform->invoke($model, new MessageBag(...\array_slice($input->getMessages(), 0, 2)), $options);
    }

    #[Override]
    public function getModelCatalog(): ModelCatalogInterface
    {
        return $this->scriptedAuditPlatform->getModelCatalog();
    }

    /**
     * @param array<string, mixed> $options
     *
     * @return list<string>
     */
    private function toolNames(array $options): array
    {
        $tools = \is_array($options['tools'] ?? null) ? $options['tools'] : [];

        return array_values(array_map(
            static fn (Tool $tool): string => $tool->getName(),
            array_filter($tools, static fn (mixed $tool): bool => $tool instanceof Tool),
        ));
    }

    /**
     * @return list<string>
     */
    private function toolAnswers(MessageBag $messageBag): array
    {
        $answers = [];
        foreach ($messageBag->getMessages() as $message) {
            if ($message instanceof ToolCallMessage) {
                $answers[] = (string) $message->asText();
            }
        }

        return $answers;
    }
}
