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

namespace VinceAmstoutz\SymfonySecurityAuditor\Command;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\ProviderKey;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\BaseUrlPlatforms;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\BedrockMantleRoute;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\CliAgentPlatforms;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\CompoundPlatforms;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\ConfigKeyInstanceName;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\ContainerParameterSyntax;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\DeclaredPlatforms;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\EndpointPlatforms;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\EnvironmentVariableName;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\EnvPlaceholder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnsupportedEnvPlaceholderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\HandWrittenPlatforms;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\InstanceKeyedPlatforms;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\OptionalApiKeyPlatforms;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\PlatformServiceId;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\TerminalText;

/**
 * Why `init` will not write a configuration, as the sentence the user reads.
 * `forProvider()` refuses the provider's shape before an option that does not
 * apply to it, then the options in the order they are written.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class InitRefusal
{
    private const string PICK_A_NAME = 'Pick a plain name such as "%s.my_gateway".';

    /**
     * Checks the raw bytes, before `ProviderKeyNormalizer`, whose `u()` throws
     * on invalid UTF-8.
     */
    public static function forProviderText(string $provider): ?string
    {
        return match (true) {
            1 !== preg_match('//u', $provider) => 'The provider must be valid UTF-8 text.',
            !TerminalText::isPlain($provider) => 'The provider must not hold a control character, a line break or a bidirectional override.',
            '' === $provider => 'The provider must not be empty.',
            default => null,
        };
    }

    /**
     * Refuses a model that is not plain text, before any printed block quotes
     * it.
     */
    public static function forModelText(string $model): ?string
    {
        return match (true) {
            1 !== preg_match('//u', $model) => 'The model must be valid UTF-8 text.',
            !TerminalText::isPlain($model) => 'The model must not hold a control character, a line break or a bidirectional override.',
            default => null,
        };
    }

    public static function forModel(string $model, ?ProviderKey $providerKey = null): ?string
    {
        return self::forModelText($model) ?? match (true) {
            '' === $model => 'The model must not be empty.',
            !ContainerParameterSyntax::isAbsentFrom($model) => 'The model holds "%...%", which would be read as a container parameter rather than as part of its name. Give the name itself.',
            $providerKey instanceof ProviderKey && BedrockMantleRoute::applies($providerKey) && !BedrockMantleRoute::namesAVendor($model) => \sprintf('Bedrock names a model after its vendor, for example "anthropic.claude-opus-4-8" or "openai.gpt-oss-120b"; "%s" names none, so init cannot tell which Bedrock route serves it. Give the full model id.', $model),
            default => null,
        };
    }

    /**
     * Null, a platform written without a credential, passes.
     */
    public static function forEnvironmentVariable(?string $envVar): ?string
    {
        return null !== $envVar ? EnvironmentVariableName::violationFor($envVar) : null;
    }

    public static function forProvider(ProviderKey $providerKey, string $provider, InitCommandInput $initCommandInput): ?string
    {
        if ('' === $providerKey->platform) {
            return \sprintf('"%s" names no platform before the dot. Give the platform first, for example "generic.my_gateway".', $provider);
        }

        if (!DeclaredPlatforms::declares($providerKey) && !CliAgentPlatforms::declares($providerKey)) {
            return \sprintf('"%s" is not a platform the bundled symfony/ai-bundle declares, so nothing was written and no bridge was installed. Pick one of %s.', $provider, implode(', ', DeclaredPlatforms::initShapes()));
        }

        return self::forCompoundPlatform($providerKey, $provider)
            ?? self::forInstanceShape($providerKey, $provider)
            ?? self::forInapplicableBaseUrl($providerKey, $provider, $initCommandInput->baseUrl)
            ?? self::forInapplicableEndpoint($providerKey, $provider, $initCommandInput->endpoint)
            ?? self::forContradictoryCredentialOptions($initCommandInput)
            ?? self::forInapplicableApiKeyOmission($providerKey, $provider, $initCommandInput->noApiKey);
    }

    public static function forResolvedEndpoint(ProviderKey $providerKey, string $provider, ?string $endpoint): ?string
    {
        if (null === $endpoint) {
            return EndpointPlatforms::requires($providerKey)
                ? \sprintf('"%s" declares no default endpoint, so nothing was written — a configuration without one sends the request against no base URI. Re-run with --endpoint=<origin>, for example --endpoint=http://localhost:11434.', $provider)
                : null;
        }

        return self::forUrl('endpoint', $provider, $endpoint);
    }

    public static function forResolvedBaseUrl(ProviderKey $providerKey, string $provider, ?string $baseUrl): ?string
    {
        if (null === $baseUrl) {
            return BaseUrlPlatforms::accept($providerKey)
                ? \sprintf('"%s" requires a base URL, so nothing was written. Re-run with --base-url=<origin>.', $provider)
                : null;
        }

        return self::forUrl('base URL', $provider, $baseUrl);
    }

    /**
     * Accepts a whole-value `%env()%` naming a valid variable and refuses any
     * other `%` that starts no percent-encoded octet.
     */
    private static function forUrl(string $setting, string $provider, string $url): ?string
    {
        $envPlaceholder = EnvPlaceholder::in($url);
        if ($envPlaceholder instanceof EnvPlaceholder) {
            return EnvironmentVariableName::isValid($envPlaceholder->variableName) ? null : UnsupportedEnvPlaceholderException::forPlaceholder($envPlaceholder)->getMessage();
        }

        return ContainerParameterSyntax::isAbsentFromUrl($url)
            ? null
            : \sprintf('The %s for "%s" holds a "%%" that starts no percent-encoded octet (such as "%%2F"): a "%%NAME%%" would be read as a container parameter rather than as part of the URL, and a lone "%%" is not valid in one. Give the URL itself, or "%%env(VAR)%%" to read it from the environment.', $setting, $provider);
    }

    /**
     * Checked first: `init` still installs such a platform's bridge and prints
     * the block to complete.
     */
    public static function forHandWrittenPlatform(ProviderKey $providerKey, string $provider, string $configFile): ?string
    {
        $requirement = HandWrittenPlatforms::requirementOf($providerKey);

        return null !== $requirement
            ? \sprintf('"%s" needs %s, which "init" does not ask for, so %s was not written. Its bridge is installed: paste the block below into that file and replace every <placeholder>.', $provider, $requirement, $configFile)
            : null;
    }

    /**
     * Checked before the instance shape: nothing written for such a platform
     * boots in the standalone binary.
     */
    private static function forCompoundPlatform(ProviderKey $providerKey, string $provider): ?string
    {
        $service = CompoundPlatforms::serviceNeededBy($providerKey);

        return null !== $service
            ? \sprintf('"%1$s" wraps other platforms through %2$s, which only a Symfony application defines: the standalone binary has none and its config file cannot declare one, so nothing was written and no bridge was installed. Configure the platform it would wrap directly, or use %3$s from the bundle inside a Symfony application.', $provider, $service, $providerKey->platform)
            : null;
    }

    private static function forInstanceShape(ProviderKey $providerKey, string $provider): ?string
    {
        if (InstanceKeyedPlatforms::needsAnInstance($providerKey)) {
            return \sprintf('"%1$s" is configured per instance, so it needs an instance name: use "%1$s.<instance>", for example "%1$s.my_gateway".', $provider);
        }

        return self::forNamedInstance($providerKey, $provider);
    }

    /**
     * Also checked for a platform whose block `init` prints, before its bridge
     * is installed.
     */
    public static function forNamedInstance(ProviderKey $providerKey, string $provider): ?string
    {
        if (InstanceKeyedPlatforms::rejectsAnInstance($providerKey)) {
            return \sprintf('"%s" takes a single connection block and names no instance, so drop the instance and use "%s".', $provider, $providerKey->platform);
        }

        return null !== $providerKey->instance
            ? self::forInstanceName($providerKey->instance, $provider, $providerKey->platform)
            : null;
    }

    private static function forInstanceName(string $instance, string $provider, string $platform): ?string
    {
        if (!ConfigKeyInstanceName::isUsable($instance)) {
            return self::sentence('"%s" uses an instance name the config file cannot be read back with: "0", ".inf", ".nan", a YAML tag or the merge key are all read back as something else.', $provider, $platform);
        }

        if (!PlatformServiceId::accepts($instance)) {
            return self::sentence('"%s" uses an instance name holding a character a service name cannot contain: an apostrophe, a line break, a null byte, or a trailing backslash.', $provider, $platform);
        }

        if (ContainerParameterSyntax::holdsReference($instance)) {
            return self::sentence('"%s" uses an instance name holding "%%...%%", which would be read as a container parameter rather than as part of the name.', $provider, $platform);
        }

        return null;
    }

    private static function forInapplicableBaseUrl(ProviderKey $providerKey, string $provider, ?string $baseUrl): ?string
    {
        return null !== $baseUrl && !BaseUrlPlatforms::accept($providerKey)
            ? \sprintf('--base-url applies to the platforms that expose one (%s); "%s" has no base_url key%s.', implode(', ', BaseUrlPlatforms::writableShapes()), $provider, EndpointPlatforms::accept($providerKey) ? ' — it names the same thing endpoint, so use --endpoint' : '')
            : null;
    }

    private static function forInapplicableEndpoint(ProviderKey $providerKey, string $provider, ?string $endpoint): ?string
    {
        return null !== $endpoint && !EndpointPlatforms::accept($providerKey)
            ? \sprintf('--endpoint applies to the platforms that declare one (%s); "%s" has no endpoint key%s.', implode(', ', EndpointPlatforms::NAMES), $provider, BaseUrlPlatforms::accept($providerKey) ? ' — it names the same thing base_url, so use --base-url' : '')
            : null;
    }

    /**
     * Checked before the platform, whatever it is.
     */
    private static function forContradictoryCredentialOptions(InitCommandInput $initCommandInput): ?string
    {
        return $initCommandInput->noApiKey && null !== $initCommandInput->envVar
            ? '--no-api-key and --env-var contradict each other: one writes no credential, the other names the variable to read it from. Pass whichever you meant, not both.'
            : null;
    }

    private static function forInapplicableApiKeyOmission(ProviderKey $providerKey, string $provider, bool $noApiKey): ?string
    {
        return $noApiKey && !OptionalApiKeyPlatforms::accept($providerKey)
            ? \sprintf('--no-api-key applies to the platforms whose key is optional (%s); "%s" requires one, and the container refuses a connection block without it.', implode(', ', OptionalApiKeyPlatforms::NAMES), $provider)
            : null;
    }

    private static function sentence(string $reason, string $provider, string $platform): string
    {
        return \sprintf('%s %s', \sprintf($reason, $provider), \sprintf(self::PICK_A_NAME, $platform));
    }
}
