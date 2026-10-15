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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\Exception;

use RuntimeException;
use Throwable;

/** @internal not part of the BC promise — see docs/versioning.md */
final class UnreadableYamlException extends RuntimeException
{
    public static function tooLarge(int $bytes, int $limit): self
    {
        return new self(\sprintf('it holds %d bytes, more than the %d the audit reads', $bytes, $limit));
    }

    public static function nestedTooDeep(int $limit): self
    {
        return new self(\sprintf('it is nested more than the %d levels deep the audit reads', $limit));
    }

    public static function tooManyImports(int $imports, int $limit): self
    {
        return new self(\sprintf('it imports %d resources, more than the %d the audit follows', $imports, $limit));
    }

    public static function importedTooDeep(int $limit): self
    {
        return new self(\sprintf('it is imported more than %d levels deep', $limit));
    }

    public static function beyondFileBudget(int $limit): self
    {
        return new self(\sprintf('the audit reads at most %d configuration files', $limit));
    }

    public static function beyondByteBudget(int $limit): self
    {
        return new self(\sprintf('the audit reads at most %d bytes of configuration', $limit));
    }

    public static function unparseable(Throwable $throwable): self
    {
        return new self(\sprintf('it is not valid YAML: %s', $throwable->getMessage()), previous: $throwable);
    }
}
