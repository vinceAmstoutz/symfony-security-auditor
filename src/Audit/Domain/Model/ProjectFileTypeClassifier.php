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
            self::isControllerPath($path) => ProjectFileType::CONTROLLER,
            self::looksLikeApiResource($path, $content) => ProjectFileType::API_RESOURCE,
            self::looksLikeLiveComponent($path, $content) => ProjectFileType::LIVE_COMPONENT,
            self::looksLikeController($path, $content) => ProjectFileType::CONTROLLER,
            self::isEntityPath($path), self::looksLikeEntity($path, $content) => ProjectFileType::ENTITY,
            self::isVoterPath($path), self::looksLikeVoter($path, $content) => ProjectFileType::VOTER,
            self::isRepositoryPath($path), self::looksLikeRepository($path, $content) => ProjectFileType::REPOSITORY,
            self::isFormPath($path), self::looksLikeForm($path, $content) => ProjectFileType::FORM,
            str_ends_with($path, 'Authenticator.php') => ProjectFileType::AUTHENTICATOR,
            self::isMessengerHandlerPath($path), self::looksLikeMessengerHandler($path, $content) => ProjectFileType::MESSENGER_HANDLER,
            self::isWebhookConsumerPath($path), self::looksLikeWebhookConsumer($path, $content) => ProjectFileType::WEBHOOK_CONSUMER,
            str_ends_with($path, 'Subscriber.php') || str_ends_with($path, 'EventListener.php') => ProjectFileType::EVENT_SUBSCRIBER,
            str_ends_with($path, 'Normalizer.php') || str_ends_with($path, 'Denormalizer.php') => ProjectFileType::NORMALIZER,
            str_ends_with($path, 'ScheduleProvider.php') || str_ends_with($path, 'Schedule.php') => ProjectFileType::SCHEDULER,
            self::looksLikeTwigExtension($path, $content) => ProjectFileType::TWIG_EXTENSION,
            str_ends_with($path, '.twig') => ProjectFileType::TEMPLATE,
            str_ends_with($path, '.yaml') || str_ends_with($path, '.yml') || str_ends_with($path, '.xml'), self::isDotenvPath($path) => ProjectFileType::CONFIG,
            str_ends_with($path, '.php') => ProjectFileType::PHP,
            default => ProjectFileType::OTHER,
        };
    }

    private static function isControllerPath(string $path): bool
    {
        return str_ends_with($path, 'Controller.php')
            || (str_contains($path, '/Controller/') && str_ends_with($path, '.php'));
    }

    private static function looksLikeController(string $path, string $content): bool
    {
        return str_ends_with($path, '.php')
            && (str_contains($content, 'extends AbstractController')
                || str_contains($content, '#[AsController')
                || str_contains($content, '#[Route'));
    }

    private static function looksLikeApiResource(string $path, string $content): bool
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

    private static function looksLikeLiveComponent(string $path, string $content): bool
    {
        return str_ends_with($path, '.php')
            && str_contains($content, '#[AsLiveComponent');
    }

    private static function isEntityPath(string $path): bool
    {
        return str_contains($path, '/Entity/')
            || str_contains($path, '/Entities/');
    }

    private static function looksLikeEntity(string $path, string $content): bool
    {
        return str_ends_with($path, '.php')
            && (str_contains($content, '#[ORM\\Entity')
                || str_contains($content, '@ORM\\Entity'));
    }

    private static function isVoterPath(string $path): bool
    {
        return str_ends_with($path, 'Voter.php')
            || (str_contains($path, '/Voter/') && str_ends_with($path, '.php'));
    }

    private static function looksLikeVoter(string $path, string $content): bool
    {
        return str_ends_with($path, '.php')
            && (str_contains($content, 'implements VoterInterface')
                || str_contains($content, 'extends Voter'));
    }

    private static function isRepositoryPath(string $path): bool
    {
        return str_ends_with($path, 'Repository.php')
            || (str_contains($path, '/Repository/') && str_ends_with($path, '.php'));
    }

    private static function looksLikeRepository(string $path, string $content): bool
    {
        return str_ends_with($path, '.php')
            && (str_contains($content, 'extends ServiceEntityRepository')
                || str_contains($content, 'extends EntityRepository'));
    }

    private static function isFormPath(string $path): bool
    {
        return str_contains($path, '/Form/')
            && str_ends_with($path, 'Type.php');
    }

    private static function looksLikeForm(string $path, string $content): bool
    {
        return str_ends_with($path, '.php')
            && str_contains($content, 'extends AbstractType');
    }

    private static function looksLikeTwigExtension(string $path, string $content): bool
    {
        return str_ends_with($path, '.php')
            && (str_contains($content, 'implements ExtensionInterface')
                || str_contains($content, 'extends AbstractExtension'));
    }

    private static function isMessengerHandlerPath(string $path): bool
    {
        return str_ends_with($path, 'MessageHandler.php')
            || (str_contains($path, '/MessageHandler/') && str_ends_with($path, '.php'));
    }

    private static function looksLikeMessengerHandler(string $path, string $content): bool
    {
        return str_ends_with($path, '.php')
            && str_contains($content, '#[AsMessageHandler');
    }

    private static function isWebhookConsumerPath(string $path): bool
    {
        return str_ends_with($path, 'WebhookConsumer.php')
            || str_ends_with($path, 'WebhookParser.php')
            || (str_contains($path, '/Webhook/') && str_ends_with($path, '.php'));
    }

    private static function looksLikeWebhookConsumer(string $path, string $content): bool
    {
        return str_ends_with($path, '.php')
            && (str_contains($content, '#[AsRemoteEventConsumer')
                || str_contains($content, 'implements RemoteEventConsumerInterface')
                || str_contains($content, 'implements RequestParserInterface'));
    }

    private static function isDotenvPath(string $path): bool
    {
        return str_starts_with(basename($path), '.env')
            && !str_ends_with($path, '.php');
    }
}
