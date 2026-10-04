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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception;

use InvalidArgumentException;
use Symfony\Component\DependencyInjection\EnvVarProcessor;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\CredentialIdentity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\EnvironmentVariableName;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\EnvPlaceholder;

/** @internal not part of the BC promise — see docs/versioning.md */
final class UnsupportedEnvPlaceholderException extends InvalidArgumentException
{
    private const string PROCESSOR_SEPARATOR = ':';

    public static function forPlaceholder(EnvPlaceholder $envPlaceholder): self
    {
        return str_contains($envPlaceholder->variableName, self::PROCESSOR_SEPARATOR)
            ? self::forProcessor($envPlaceholder)
            : self::forName($envPlaceholder);
    }

    private static function forProcessor(EnvPlaceholder $envPlaceholder): self
    {
        return new self(\sprintf(
            'The placeholder "%s" applies an env processor, and the standalone binary applies none (trim:, string:, default:, …): it reads only "%%env(VAR)%%" and "%%env(file:VAR)%%", so name the variable directly — "%%env(VAR)%%" rather than "%%env(trim:VAR)%%".',
            self::quoted($envPlaceholder),
        ));
    }

    private static function forName(EnvPlaceholder $envPlaceholder): self
    {
        return new self(\sprintf(
            'The placeholder "%s" names no variable a shell can export: %s The standalone binary reads only "%%env(VAR)%%" and "%%env(file:VAR)%%".',
            self::quoted($envPlaceholder),
            EnvironmentVariableName::violationFor($envPlaceholder->variableName),
        ));
    }

    /**
     * The placeholder is quoted so the line of the config to fix can be found,
     * but never so that a key pasted into it is echoed: each processor is
     * shown only when Symfony names it so, the variable as
     * `EnvironmentVariableName::shown()` quotes a refused name, and an
     * expression holding anything else is masked as a key is, however short
     * — its colons may be part of the key.
     */
    private static function quoted(EnvPlaceholder $envPlaceholder): string
    {
        $processors = explode(self::PROCESSOR_SEPARATOR, $envPlaceholder->variableName);
        $name = array_pop($processors);
        $expression = self::namesOnlyProcessors($processors)
            ? implode(self::PROCESSOR_SEPARATOR, [...$processors, EnvironmentVariableName::shown($name)])
            : CredentialIdentity::of($envPlaceholder->variableName)->maskedPreview;

        return \sprintf('%%env(%s%s)%%', $envPlaceholder->readsFile ? 'file:' : '', $expression);
    }

    /**
     * @param list<string> $segments
     */
    private static function namesOnlyProcessors(array $segments): bool
    {
        return [] === array_diff($segments, ['', ...array_keys(EnvVarProcessor::getProvidedTypes())]);
    }
}
