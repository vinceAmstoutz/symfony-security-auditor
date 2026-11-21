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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM;

use Symfony\AI\Platform\Result\DeferredResult;
use Symfony\AI\Platform\Result\RawHttpResult;

use function Symfony\Component\String\u;

/**
 * Whether a gateway answered a streamed request with one JSON document, as
 * a gateway that cannot stream does: the bridge would read it as an empty
 * stream, so it is read as the buffered answer it is.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class UnstreamedAnswer
{
    public static function in(DeferredResult $streamedResult): bool
    {
        $rawResult = $streamedResult->getRawResult();
        if (!$rawResult instanceof RawHttpResult) {
            return false;
        }

        $contentType = $rawResult->getObject()->getHeaders(false)['content-type'][0] ?? '';

        return u($contentType)->lower()->startsWith('application/json');
    }
}
