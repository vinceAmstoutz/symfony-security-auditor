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
 * A provider failure quotes the URL it was sent to, and some providers take
 * their API key in that URL's query (Vertex AI's `?key=`). The message of an
 * exception built from such a failure goes to logs, the console and MCP
 * clients, so the value of every credential query parameter is replaced
 * before it is stored. A message the redaction could not evaluate is withheld
 * whole, never returned as it was.
 *
 * @internal not part of the BC promise — see docs/versioning.md
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
