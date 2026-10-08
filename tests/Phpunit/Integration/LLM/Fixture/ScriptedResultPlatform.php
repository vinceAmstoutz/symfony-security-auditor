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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture;

use Override;
use RuntimeException;
use Symfony\AI\Platform\Message\MessageBag;
use Symfony\AI\Platform\Message\MessageInterface;
use Symfony\AI\Platform\Model;
use Symfony\AI\Platform\ModelCatalog\FallbackModelCatalog;
use Symfony\AI\Platform\ModelCatalog\ModelCatalogInterface;
use Symfony\AI\Platform\PlainConverter;
use Symfony\AI\Platform\PlatformInterface;
use Symfony\AI\Platform\Result\DeferredResult;
use Symfony\AI\Platform\Result\InMemoryRawResult;
use Symfony\AI\Platform\Result\ResultInterface;

/**
 * Test fake: answers each invocation with the next scripted result and keeps
 * the messages and the options each request carried, so a test can read what
 * the model was sent on every round.
 */
final class ScriptedResultPlatform implements PlatformInterface
{
    /** @var list<list<MessageInterface>> */
    public array $requests = [];

    /** @var list<array<string, mixed>> */
    public array $options = [];

    /**
     * @param list<ResultInterface> $results
     */
    public function __construct(
        private array $results,
    ) {}

    #[Override]
    public function invoke(Model|string $model, array|string|object $input, array $options = []): DeferredResult
    {
        if ($input instanceof MessageBag) {
            $this->requests[] = $input->getMessages();
        }

        $this->options[] = $options;

        $result = array_shift($this->results);
        if (!$result instanceof ResultInterface) {
            throw new RuntimeException('ScriptedResultPlatform invoked more times than scripted.');
        }

        return new DeferredResult(
            new PlainConverter($result),
            new InMemoryRawResult(['text' => ''], [], (object) []),
            $options,
        );
    }

    #[Override]
    public function getModelCatalog(): ModelCatalogInterface
    {
        return new FallbackModelCatalog();
    }
}
