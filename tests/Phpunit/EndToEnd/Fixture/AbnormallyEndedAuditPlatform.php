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
use Symfony\AI\Platform\FinishReason\FinishReason;
use Symfony\AI\Platform\FinishReason\FinishReasonCase;
use Symfony\AI\Platform\Model;
use Symfony\AI\Platform\ModelCatalog\FallbackModelCatalog;
use Symfony\AI\Platform\ModelCatalog\ModelCatalogInterface;
use Symfony\AI\Platform\PlainConverter;
use Symfony\AI\Platform\PlatformInterface;
use Symfony\AI\Platform\Result\DeferredResult;
use Symfony\AI\Platform\Result\InMemoryRawResult;
use Symfony\AI\Platform\Result\TextResult;

/**
 * Answers every call the way the Gemini and Vertex AI bridges convert a
 * candidate that ends on `MALFORMED_FUNCTION_CALL` with no content part: an
 * empty text whose finish reason has no normalized equivalent.
 */
final readonly class AbnormallyEndedAuditPlatform implements PlatformInterface
{
    private ModelCatalogInterface $modelCatalog;

    public function __construct()
    {
        $this->modelCatalog = new FallbackModelCatalog();
    }

    /**
     * @param array<array-key, mixed>|string|object $input
     * @param array<string, mixed>                  $options
     */
    #[Override]
    public function invoke(Model|string $model, array|string|object $input, array $options = []): DeferredResult
    {
        $textResult = new TextResult('');
        $textResult->getMetadata()->add('finish_reason', new FinishReason(FinishReasonCase::OTHER, 'MALFORMED_FUNCTION_CALL'));

        return new DeferredResult(new PlainConverter($textResult), new InMemoryRawResult(['candidates' => []]), $options);
    }

    #[Override]
    public function getModelCatalog(): ModelCatalogInterface
    {
        return $this->modelCatalog;
    }
}
