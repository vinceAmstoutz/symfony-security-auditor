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

final readonly class ProjectFileTypeClassifier
{
    public static function classify(string $path, string $content): ProjectFileType
    {
        return match (true) {
            ProjectFileContentSignatures::looksLikeEasyAdminCrud($path, $content) => ProjectFileType::EASYADMIN_CRUD,
            self::isControllerPath($path) => ProjectFileType::CONTROLLER,
            ProjectFileContentSignatures::looksLikeApiResource($path, $content) => ProjectFileType::API_RESOURCE,
            ProjectFileContentSignatures::looksLikeLiveComponent($path, $content) => ProjectFileType::LIVE_COMPONENT,
            ProjectFileContentSignatures::looksLikeController($path, $content) => ProjectFileType::CONTROLLER,
            self::isVoterPath($path), ProjectFileContentSignatures::looksLikeVoter($path, $content) => ProjectFileType::VOTER,
            self::isRepositoryPath($path), ProjectFileContentSignatures::looksLikeRepository($path, $content) => ProjectFileType::REPOSITORY,
            self::isFormPath($path), ProjectFileContentSignatures::looksLikeForm($path, $content) => ProjectFileType::FORM,
            self::isEntityPath($path), ProjectFileContentSignatures::looksLikeEntity($path, $content) => ProjectFileType::ENTITY,
            str_ends_with($path, 'Authenticator.php'), ProjectFileContentSignatures::looksLikeAuthenticator($path, $content) => ProjectFileType::AUTHENTICATOR,
            self::isMessengerHandlerPath($path), ProjectFileContentSignatures::looksLikeMessengerHandler($path, $content) => ProjectFileType::MESSENGER_HANDLER,
            self::isUseCasePath($path), ProjectFileContentSignatures::looksLikeUseCase($path, $content), ProjectFileContentSignatures::looksLikeApiPlatformState($path, $content) => ProjectFileType::USE_CASE,
            self::isWebhookConsumerPath($path), ProjectFileContentSignatures::looksLikeWebhookConsumer($path, $content) => ProjectFileType::WEBHOOK_CONSUMER,
            str_ends_with($path, 'Subscriber.php') || str_ends_with($path, 'EventListener.php'), ProjectFileContentSignatures::looksLikeEventSubscriber($path, $content) => ProjectFileType::EVENT_SUBSCRIBER,
            str_ends_with($path, 'Normalizer.php') || str_ends_with($path, 'Denormalizer.php'), ProjectFileContentSignatures::looksLikeNormalizer($path, $content) => ProjectFileType::NORMALIZER,
            str_ends_with($path, 'ScheduleProvider.php') || str_ends_with($path, 'Schedule.php'), ProjectFileContentSignatures::looksLikeScheduler($path, $content) => ProjectFileType::SCHEDULER,
            self::isLdapServicePath($path), ProjectFileContentSignatures::looksLikeLdapService($path, $content) => ProjectFileType::LDAP_SERVICE,
            self::isSonataAdminPath($path) && str_contains($content, 'Sonata\\AdminBundle'), ProjectFileContentSignatures::looksLikeSonataAdmin($path, $content) => ProjectFileType::SONATA_ADMIN,
            ProjectFileContentSignatures::looksLikeTwigExtension($path, $content) => ProjectFileType::TWIG_EXTENSION,
            str_ends_with($path, '.twig') => ProjectFileType::TEMPLATE,
            str_ends_with($path, '.yaml') || str_ends_with($path, '.yml') || str_ends_with($path, '.xml'), self::isDotenvPath($path) => ProjectFileType::CONFIG,
            self::isActionPath($path) => ProjectFileType::CONTROLLER,
            str_ends_with($path, '.php') => ProjectFileType::PHP,
            default => ProjectFileType::OTHER,
        };
    }

    private static function isControllerPath(string $path): bool
    {
        return str_ends_with($path, 'Controller.php')
            || (str_contains($path, '/Controller/') && str_ends_with($path, '.php'));
    }

    private static function isActionPath(string $path): bool
    {
        return str_ends_with($path, 'Action.php')
            && (str_contains($path, '/Action/') || str_contains($path, '/Actions/'));
    }

    private static function isEntityPath(string $path): bool
    {
        return str_contains($path, '/Entity/')
            || str_contains($path, '/Entities/');
    }

    private static function isVoterPath(string $path): bool
    {
        return str_ends_with($path, 'Voter.php')
            || (str_contains($path, '/Voter/') && str_ends_with($path, '.php'));
    }

    private static function isRepositoryPath(string $path): bool
    {
        return str_ends_with($path, 'Repository.php')
            || ((str_contains($path, '/Repository/') || str_contains($path, '/Sql/')) && str_ends_with($path, '.php'));
    }

    private static function isFormPath(string $path): bool
    {
        return str_contains($path, '/Form/')
            && str_ends_with($path, 'Type.php');
    }

    private static function isLdapServicePath(string $path): bool
    {
        return str_ends_with($path, 'Ldap.php')
            || (str_contains($path, '/Ldap/') && str_ends_with($path, '.php'));
    }

    private static function isSonataAdminPath(string $path): bool
    {
        return str_ends_with($path, 'Admin.php')
            || (str_contains($path, '/Admin/') && str_ends_with($path, '.php'));
    }

    private static function isMessengerHandlerPath(string $path): bool
    {
        return str_ends_with($path, 'MessageHandler.php')
            || (str_contains($path, '/MessageHandler/') && str_ends_with($path, '.php'));
    }

    private static function isUseCasePath(string $path): bool
    {
        return str_ends_with($path, 'CommandHandler.php')
            || str_ends_with($path, 'QueryHandler.php')
            || (str_ends_with($path, 'Handler.php') && self::isInAHandlerDirectory($path))
            || (str_contains($path, '/UseCase/') && str_ends_with($path, '.php'));
    }

    private static function isInAHandlerDirectory(string $path): bool
    {
        foreach (['/Command/', '/Query/', '/CommandHandler/', '/QueryHandler/', '/Application/'] as $directory) {
            if (str_contains($path, $directory)) {
                return true;
            }
        }

        return false;
    }

    private static function isWebhookConsumerPath(string $path): bool
    {
        return str_ends_with($path, 'WebhookConsumer.php')
            || str_ends_with($path, 'WebhookParser.php')
            || (str_contains($path, '/Webhook/') && str_ends_with($path, '.php'));
    }

    private static function isDotenvPath(string $path): bool
    {
        return str_starts_with(basename($path), '.env')
            && !str_ends_with($path, '.php');
    }
}
