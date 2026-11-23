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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception;

/**
 * Replaces the value of every credential query parameter (Vertex AI's `?key=`)
 * in a provider failure message, which reaches logs, the console and MCP
 * clients. Withholds the whole of a message it cannot evaluate.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class ProviderMessageRedactor
{
    private const string CREDENTIAL_QUERY_PARAMETER = '/([?&](?:key|api_key|apikey|access_token|token)=)[^&#\s"\'<>)\]]+/i';

    private const string REDACTED_VALUE = '${1}***REDACTED***';

    private const string WITHHELD_MESSAGE = '[provider message withheld: it could not be checked for credentials]';

    public static function redact(string $message): string
    {
        return preg_replace(self::CREDENTIAL_QUERY_PARAMETER, self::REDACTED_VALUE, $message) ?? self::WITHHELD_MESSAGE;
    }
}
