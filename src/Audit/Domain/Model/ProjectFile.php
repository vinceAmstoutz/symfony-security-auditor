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

use InvalidArgumentException;

final readonly class ProjectFile
{
    private function __construct(
        private string $relativePath,
        private string $absolutePath,
        private string $content,
        private ProjectFileType $projectFileType,
        private int $linesCount,
    ) {}

    public static function create(
        string $relativePath,
        string $absolutePath,
        string $content,
    ): self {
        if ('' === trim($relativePath)) {
            throw new InvalidArgumentException('Relative path cannot be empty');
        }

        return new self(
            relativePath: $relativePath,
            absolutePath: $absolutePath,
            content: $content,
            projectFileType: self::detectType($relativePath, $content),
            linesCount: substr_count($content, "\n") + 1,
        );
    }

    public function relativePath(): string
    {
        return $this->relativePath;
    }

    public function absolutePath(): string
    {
        return $this->absolutePath;
    }

    public function content(): string
    {
        return $this->content;
    }

    public function type(): string
    {
        return $this->projectFileType->value;
    }

    public function fileType(): ProjectFileType
    {
        return $this->projectFileType;
    }

    public function linesCount(): int
    {
        return $this->linesCount;
    }

    public function contentHash(): string
    {
        return hash('sha256', $this->content);
    }

    public function isController(): bool
    {
        if (self::isControllerPath($this->relativePath)) {
            return true;
        }

        return self::looksLikeController($this->relativePath, $this->content);
    }

    public function isEntity(): bool
    {
        if (self::isEntityPath($this->relativePath)) {
            return true;
        }

        return self::looksLikeEntity($this->relativePath, $this->content);
    }

    public function isVoter(): bool
    {
        if (self::isVoterPath($this->relativePath)) {
            return true;
        }

        return self::looksLikeVoter($this->relativePath, $this->content);
    }

    public function isRepository(): bool
    {
        if (self::isRepositoryPath($this->relativePath)) {
            return true;
        }

        return self::looksLikeRepository($this->relativePath, $this->content);
    }

    public function isForm(): bool
    {
        if (self::isFormPath($this->relativePath)) {
            return true;
        }

        return self::looksLikeForm($this->relativePath, $this->content);
    }

    public function isMessengerHandler(): bool
    {
        return str_ends_with($this->relativePath, 'MessageHandler.php')
            || (str_contains($this->relativePath, '/MessageHandler/') && str_ends_with($this->relativePath, '.php'));
    }

    public function isAuthenticator(): bool
    {
        return str_ends_with($this->relativePath, 'Authenticator.php');
    }

    public function isEventSubscriber(): bool
    {
        return str_ends_with($this->relativePath, 'Subscriber.php')
            || str_ends_with($this->relativePath, 'EventListener.php');
    }

    public function isNormalizer(): bool
    {
        return str_ends_with($this->relativePath, 'Normalizer.php')
            || str_ends_with($this->relativePath, 'Denormalizer.php');
    }

    public function isWebhookConsumer(): bool
    {
        return str_ends_with($this->relativePath, 'WebhookConsumer.php')
            || str_ends_with($this->relativePath, 'WebhookParser.php')
            || (str_contains($this->relativePath, '/Webhook/') && str_ends_with($this->relativePath, '.php'));
    }

    public function isScheduler(): bool
    {
        return str_ends_with($this->relativePath, 'ScheduleProvider.php')
            || str_ends_with($this->relativePath, 'Schedule.php');
    }

    public function isService(): bool
    {
        return !$this->matchesKnownComponentType()
            && str_ends_with($this->relativePath, '.php');
    }

    private function matchesKnownComponentType(): bool
    {
        if ($this->matchesDomainComponentType()) {
            return true;
        }

        return $this->matchesMessagingComponentType();
    }

    private function matchesDomainComponentType(): bool
    {
        if ($this->isController()) {
            return true;
        }

        if ($this->isEntity()) {
            return true;
        }

        if ($this->isVoter()) {
            return true;
        }

        if ($this->isRepository()) {
            return true;
        }

        return $this->isForm();
    }

    private function matchesMessagingComponentType(): bool
    {
        if ($this->isMessengerHandler()) {
            return true;
        }

        if ($this->isAuthenticator()) {
            return true;
        }

        if ($this->isEventSubscriber()) {
            return true;
        }

        if ($this->isNormalizer()) {
            return true;
        }

        if ($this->isWebhookConsumer()) {
            return true;
        }

        return $this->isScheduler();
    }

    public function isTemplate(): bool
    {
        return str_ends_with($this->relativePath, '.twig')
            || str_ends_with($this->relativePath, '.html.twig');
    }

    public function isConfiguration(): bool
    {
        return str_ends_with($this->relativePath, '.yaml')
            || str_ends_with($this->relativePath, '.yml')
            || str_ends_with($this->relativePath, '.xml')
            || self::isDotenvPath($this->relativePath);
    }

    private static function isDotenvPath(string $path): bool
    {
        return str_starts_with(basename($path), '.env')
            && !str_ends_with($path, '.php');
    }

    public function containsKeyword(string $keyword): bool
    {
        return str_contains($this->content, $keyword);
    }

    public function hasSecurityAnnotations(): bool
    {
        if ($this->containsKeyword('#[IsGranted')) {
            return true;
        }

        if ($this->containsKeyword('@IsGranted')) {
            return true;
        }

        if ($this->containsKeyword('$this->denyAccessUnlessGranted')) {
            return true;
        }

        return $this->containsKeyword('security:');
    }

    /**
     * @return array<string, bool|int|string>
     */
    public function toArray(): array
    {
        return [
            'path' => $this->relativePath,
            'type' => $this->projectFileType->value,
            'lines' => $this->linesCount,
            'is_controller' => $this->isController(),
            'is_entity' => $this->isEntity(),
            'is_voter' => $this->isVoter(),
            'is_repository' => $this->isRepository(),
            'is_form' => $this->isForm(),
            'has_security_annotations' => $this->hasSecurityAnnotations(),
        ];
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
            && 1 === preg_match('/#\[\s*(?:Get|GetCollection|Post|Put|Patch|Delete|Query|QueryCollection|Mutation)\b/', $content);
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

    private static function detectType(string $path, string $content): ProjectFileType
    {
        return match (true) {
            self::isControllerPath($path), self::looksLikeController($path, $content) => ProjectFileType::CONTROLLER,
            self::looksLikeApiResource($path, $content) => ProjectFileType::API_RESOURCE,
            self::looksLikeLiveComponent($path, $content) => ProjectFileType::LIVE_COMPONENT,
            self::isEntityPath($path), self::looksLikeEntity($path, $content) => ProjectFileType::ENTITY,
            self::isVoterPath($path), self::looksLikeVoter($path, $content) => ProjectFileType::VOTER,
            self::isRepositoryPath($path), self::looksLikeRepository($path, $content) => ProjectFileType::REPOSITORY,
            self::isFormPath($path), self::looksLikeForm($path, $content) => ProjectFileType::FORM,
            str_ends_with($path, 'Authenticator.php') => ProjectFileType::AUTHENTICATOR,
            str_ends_with($path, 'MessageHandler.php') || str_contains($path, '/MessageHandler/') => ProjectFileType::MESSENGER_HANDLER,
            str_ends_with($path, 'WebhookConsumer.php') || str_ends_with($path, 'WebhookParser.php') || str_contains($path, '/Webhook/') => ProjectFileType::WEBHOOK_CONSUMER,
            str_ends_with($path, 'Subscriber.php') || str_ends_with($path, 'EventListener.php') => ProjectFileType::EVENT_SUBSCRIBER,
            str_ends_with($path, 'Normalizer.php') || str_ends_with($path, 'Denormalizer.php') => ProjectFileType::NORMALIZER,
            str_ends_with($path, 'ScheduleProvider.php') || str_ends_with($path, 'Schedule.php') => ProjectFileType::SCHEDULER,
            self::looksLikeTwigExtension($path, $content) => ProjectFileType::TWIG_EXTENSION,
            str_ends_with($path, '.twig') => ProjectFileType::TEMPLATE,
            str_ends_with($path, '.yaml') || str_ends_with($path, '.yml'), self::isDotenvPath($path) => ProjectFileType::CONFIG,
            str_ends_with($path, '.php') => ProjectFileType::PHP,
            default => ProjectFileType::OTHER,
        };
    }
}
