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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan;

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProjectFileTypeClassifierInterface;

/**
 * Symfony's file conventions: the framework-specific half of file discovery.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class SymfonyProjectFileTypeClassifier implements ProjectFileTypeClassifierInterface
{
    private const array FOREIGN_TYPES = [
        ProjectFileType::POLICY,
        ProjectFileType::ELOQUENT_MODEL,
        ProjectFileType::FORM_REQUEST,
        ProjectFileType::BLADE_TEMPLATE,
        ProjectFileType::JOB,
        ProjectFileType::MIDDLEWARE,
        ProjectFileType::GUARD,
    ];

    /**
     * Every case except the ones another framework's profile owns.
     *
     * @return list<ProjectFileType>
     */
    #[Override]
    public function supportedTypes(): array
    {
        return array_values(array_filter(
            ProjectFileType::cases(),
            static fn (ProjectFileType $projectFileType): bool => !\in_array($projectFileType, self::FOREIGN_TYPES, true),
        ));
    }

    #[Override]
    public function classify(string $relativePath, string $content): ProjectFileType
    {
        return match (true) {
            $this->looksLikeEasyAdminCrud($relativePath, $content) => ProjectFileType::EASYADMIN_CRUD,
            $this->isControllerPath($relativePath) => ProjectFileType::CONTROLLER,
            $this->looksLikeApiResource($relativePath, $content) => ProjectFileType::API_RESOURCE,
            $this->looksLikeLiveComponent($relativePath, $content) => ProjectFileType::LIVE_COMPONENT,
            $this->looksLikeController($relativePath, $content) => ProjectFileType::CONTROLLER,
            $this->isVoterPath($relativePath), $this->looksLikeVoter($relativePath, $content) => ProjectFileType::VOTER,
            $this->isRepositoryPath($relativePath), $this->looksLikeRepository($relativePath, $content) => ProjectFileType::REPOSITORY,
            $this->isFormPath($relativePath), $this->looksLikeForm($relativePath, $content) => ProjectFileType::FORM,
            $this->isEntityPath($relativePath), $this->looksLikeEntity($relativePath, $content) => ProjectFileType::ENTITY,
            str_ends_with($relativePath, 'Authenticator.php'), $this->looksLikeAuthenticator($relativePath, $content) => ProjectFileType::AUTHENTICATOR,
            $this->isMessengerHandlerPath($relativePath), $this->looksLikeMessengerHandler($relativePath, $content) => ProjectFileType::MESSENGER_HANDLER,
            $this->isWebhookConsumerPath($relativePath), $this->looksLikeWebhookConsumer($relativePath, $content) => ProjectFileType::WEBHOOK_CONSUMER,
            str_ends_with($relativePath, 'Subscriber.php') || str_ends_with($relativePath, 'EventListener.php'), $this->looksLikeEventSubscriber($relativePath, $content) => ProjectFileType::EVENT_SUBSCRIBER,
            str_ends_with($relativePath, 'Normalizer.php') || str_ends_with($relativePath, 'Denormalizer.php'), $this->looksLikeNormalizer($relativePath, $content) => ProjectFileType::NORMALIZER,
            str_ends_with($relativePath, 'ScheduleProvider.php') || str_ends_with($relativePath, 'Schedule.php'), $this->looksLikeScheduler($relativePath, $content) => ProjectFileType::SCHEDULER,
            $this->isLdapServicePath($relativePath), $this->looksLikeLdapService($relativePath, $content) => ProjectFileType::LDAP_SERVICE,
            $this->isSonataAdminPath($relativePath), $this->looksLikeSonataAdmin($relativePath, $content) => ProjectFileType::SONATA_ADMIN,
            $this->looksLikeTwigExtension($relativePath, $content) => ProjectFileType::TWIG_EXTENSION,
            str_ends_with($relativePath, '.twig') => ProjectFileType::TEMPLATE,
            str_ends_with($relativePath, '.yaml') || str_ends_with($relativePath, '.yml') || str_ends_with($relativePath, '.xml'), $this->isDotenvPath($relativePath) => ProjectFileType::CONFIG,
            str_ends_with($relativePath, '.php') => ProjectFileType::PHP,
            default => ProjectFileType::OTHER,
        };
    }

    private function looksLikeEasyAdminCrud(string $path, string $content): bool
    {
        return str_ends_with($path, '.php')
            && (str_contains($content, 'extends AbstractCrudController')
                || str_contains($content, 'implements CrudControllerInterface'));
    }

    private function isControllerPath(string $path): bool
    {
        return str_ends_with($path, 'Controller.php')
            || (str_contains($path, '/Controller/') && str_ends_with($path, '.php'));
    }

    private function looksLikeController(string $path, string $content): bool
    {
        return str_ends_with($path, '.php')
            && (str_contains($content, 'extends AbstractController')
                || str_contains($content, '#[AsController')
                || str_contains($content, '#[Route'));
    }

    private function looksLikeApiResource(string $path, string $content): bool
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

    private function looksLikeLiveComponent(string $path, string $content): bool
    {
        return str_ends_with($path, '.php')
            && str_contains($content, '#[AsLiveComponent');
    }

    private function isEntityPath(string $path): bool
    {
        return str_contains($path, '/Entity/')
            || str_contains($path, '/Entities/');
    }

    private function looksLikeEntity(string $path, string $content): bool
    {
        return str_ends_with($path, '.php')
            && (str_contains($content, '#[ORM\\Entity')
                || str_contains($content, '@ORM\\Entity'));
    }

    private function isVoterPath(string $path): bool
    {
        return str_ends_with($path, 'Voter.php')
            || (str_contains($path, '/Voter/') && str_ends_with($path, '.php'));
    }

    private function looksLikeVoter(string $path, string $content): bool
    {
        return str_ends_with($path, '.php')
            && (str_contains($content, 'implements VoterInterface')
                || str_contains($content, 'extends Voter'));
    }

    private function isRepositoryPath(string $path): bool
    {
        return str_ends_with($path, 'Repository.php')
            || (str_contains($path, '/Repository/') && str_ends_with($path, '.php'));
    }

    private function looksLikeRepository(string $path, string $content): bool
    {
        return str_ends_with($path, '.php')
            && (str_contains($content, 'extends ServiceEntityRepository')
                || str_contains($content, 'extends EntityRepository'));
    }

    private function isFormPath(string $path): bool
    {
        return str_contains($path, '/Form/')
            && str_ends_with($path, 'Type.php');
    }

    private function looksLikeForm(string $path, string $content): bool
    {
        return str_ends_with($path, '.php')
            && str_contains($content, 'extends AbstractType');
    }

    private function looksLikeTwigExtension(string $path, string $content): bool
    {
        return str_ends_with($path, '.php')
            && (str_contains($content, 'implements ExtensionInterface')
                || str_contains($content, 'extends AbstractExtension'));
    }

    private function isLdapServicePath(string $path): bool
    {
        return str_ends_with($path, 'Ldap.php')
            || (str_contains($path, '/Ldap/') && str_ends_with($path, '.php'));
    }

    private function looksLikeLdapService(string $path, string $content): bool
    {
        return str_ends_with($path, '.php')
            && str_contains($content, 'Symfony\\Component\\Ldap\\Ldap');
    }

    private function isSonataAdminPath(string $path): bool
    {
        return str_ends_with($path, 'Admin.php')
            || (str_contains($path, '/Admin/') && str_ends_with($path, '.php'));
    }

    private function looksLikeSonataAdmin(string $path, string $content): bool
    {
        return str_ends_with($path, '.php')
            && str_contains($content, 'extends AbstractAdmin');
    }

    private function isMessengerHandlerPath(string $path): bool
    {
        return str_ends_with($path, 'MessageHandler.php')
            || (str_contains($path, '/MessageHandler/') && str_ends_with($path, '.php'));
    }

    private function looksLikeMessengerHandler(string $path, string $content): bool
    {
        return str_ends_with($path, '.php')
            && str_contains($content, '#[AsMessageHandler');
    }

    private function isWebhookConsumerPath(string $path): bool
    {
        return str_ends_with($path, 'WebhookConsumer.php')
            || str_ends_with($path, 'WebhookParser.php')
            || (str_contains($path, '/Webhook/') && str_ends_with($path, '.php'));
    }

    private function looksLikeWebhookConsumer(string $path, string $content): bool
    {
        return str_ends_with($path, '.php')
            && (str_contains($content, '#[AsRemoteEventConsumer')
                || str_contains($content, 'implements RemoteEventConsumerInterface')
                || str_contains($content, 'implements RequestParserInterface'));
    }

    private function looksLikeAuthenticator(string $path, string $content): bool
    {
        return str_ends_with($path, '.php')
            && str_contains($content, 'implements AuthenticatorInterface');
    }

    private function looksLikeEventSubscriber(string $path, string $content): bool
    {
        return str_ends_with($path, '.php')
            && (str_contains($content, 'implements EventSubscriberInterface')
                || str_contains($content, '#[AsEventListener'));
    }

    private function looksLikeNormalizer(string $path, string $content): bool
    {
        return str_ends_with($path, '.php')
            && (str_contains($content, 'implements NormalizerInterface')
                || str_contains($content, 'implements DenormalizerInterface'));
    }

    private function looksLikeScheduler(string $path, string $content): bool
    {
        return str_ends_with($path, '.php')
            && str_contains($content, 'implements ScheduleProviderInterface');
    }

    private function isDotenvPath(string $path): bool
    {
        return str_starts_with(basename($path), '.env')
            && !str_ends_with($path, '.php');
    }
}
