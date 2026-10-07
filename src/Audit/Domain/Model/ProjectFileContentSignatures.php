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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model;

/**
 * Recognizes, from the source of a PHP file, the framework construct it declares.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ProjectFileContentSignatures
{
    public static function looksLikeEasyAdminCrud(string $path, string $content): bool
    {
        return str_ends_with($path, '.php')
            && (str_contains($content, 'extends AbstractCrudController')
                || str_contains($content, 'implements CrudControllerInterface'));
    }

    public static function looksLikeController(string $path, string $content): bool
    {
        return str_ends_with($path, '.php')
            && (str_contains($content, 'extends AbstractController')
                || str_contains($content, '#[AsController')
                || str_contains($content, '#[Route'));
    }

    public static function looksLikeApiResource(string $path, string $content): bool
    {
        if (!str_ends_with($path, '.php')) {
            return false;
        }

        if (str_contains($content, '#[ApiResource') || str_contains($content, '@ApiResource')) {
            return true;
        }

        return str_contains($content, 'ApiPlatform\\Metadata')
            && 1 === preg_match('/#\[\s*(?:[\w\\\\]+\\\\)?(?:Get|GetCollection|Post|Put|Patch|Delete|Query|QueryCollection|Mutation)\b/', $content);
    }

    public static function looksLikeLiveComponent(string $path, string $content): bool
    {
        return str_ends_with($path, '.php')
            && str_contains($content, '#[AsLiveComponent');
    }

    public static function looksLikeEntity(string $path, string $content): bool
    {
        return str_ends_with($path, '.php')
            && (str_contains($content, '#[ORM\\Entity')
                || str_contains($content, '@ORM\\Entity'));
    }

    public static function looksLikeVoter(string $path, string $content): bool
    {
        return str_ends_with($path, '.php')
            && (str_contains($content, 'implements VoterInterface')
                || str_contains($content, 'extends Voter'));
    }

    public static function looksLikeRepository(string $path, string $content): bool
    {
        return str_ends_with($path, '.php')
            && (str_contains($content, 'extends ServiceEntityRepository')
                || str_contains($content, 'extends EntityRepository'));
    }

    public static function looksLikeForm(string $path, string $content): bool
    {
        return str_ends_with($path, '.php')
            && str_contains($content, 'extends AbstractType');
    }

    public static function looksLikeTwigExtension(string $path, string $content): bool
    {
        return str_ends_with($path, '.php')
            && (str_contains($content, 'implements ExtensionInterface')
                || str_contains($content, 'extends AbstractExtension'));
    }

    public static function looksLikeLdapService(string $path, string $content): bool
    {
        return str_ends_with($path, '.php')
            && str_contains($content, 'Symfony\\Component\\Ldap\\Ldap');
    }

    public static function looksLikeSonataAdmin(string $path, string $content): bool
    {
        return str_ends_with($path, '.php')
            && str_contains($content, 'extends AbstractAdmin');
    }

    public static function looksLikeMessengerHandler(string $path, string $content): bool
    {
        return str_ends_with($path, '.php')
            && str_contains($content, '#[AsMessageHandler');
    }

    public static function looksLikeWebhookConsumer(string $path, string $content): bool
    {
        return str_ends_with($path, '.php')
            && (str_contains($content, '#[AsRemoteEventConsumer')
                || str_contains($content, 'implements RemoteEventConsumerInterface')
                || str_contains($content, 'implements RequestParserInterface'));
    }

    public static function looksLikeAuthenticator(string $path, string $content): bool
    {
        return str_ends_with($path, '.php')
            && str_contains($content, 'implements AuthenticatorInterface');
    }

    public static function looksLikeEventSubscriber(string $path, string $content): bool
    {
        return str_ends_with($path, '.php')
            && (str_contains($content, 'implements EventSubscriberInterface')
                || str_contains($content, '#[AsEventListener'));
    }

    public static function looksLikeNormalizer(string $path, string $content): bool
    {
        return str_ends_with($path, '.php')
            && (str_contains($content, 'implements NormalizerInterface')
                || str_contains($content, 'implements DenormalizerInterface'));
    }

    public static function looksLikeScheduler(string $path, string $content): bool
    {
        return str_ends_with($path, '.php')
            && str_contains($content, 'implements ScheduleProviderInterface');
    }
}
