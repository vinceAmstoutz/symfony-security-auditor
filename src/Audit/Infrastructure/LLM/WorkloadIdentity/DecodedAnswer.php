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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\WorkloadIdentity;

use Symfony\Contracts\HttpClient\Exception\DecodingExceptionInterface;
use Symfony\Contracts\HttpClient\ResponseInterface;

/**
 * Reads an answer's JSON body whatever its status; an empty array when the
 * body is not JSON, such as a gateway's HTML page.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class DecodedAnswer
{
    /**
     * @return array<mixed>
     */
    public static function of(ResponseInterface $response): array
    {
        try {
            return $response->toArray(false);
        } catch (DecodingExceptionInterface) {
            return [];
        }
    }
}
