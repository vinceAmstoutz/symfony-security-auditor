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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;

final readonly class ProjectFile
{
    private function __construct(
        private string $relativePath,
        private string $absolutePath,
        private string $content,
        private ProjectFileType $projectFileType,
        private int $linesCount,
    ) {}

    /**
     * @throws InvalidProjectFileException
     */
    public static function create(
        string $relativePath,
        string $absolutePath,
        string $content,
    ): self {
        if ('' === trim($relativePath)) {
            throw InvalidProjectFileException::forBlankRelativePath();
        }

        return new self(
            relativePath: $relativePath,
            absolutePath: $absolutePath,
            content: $content,
            projectFileType: ProjectFileTypeClassifier::classify($relativePath, $content),
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

    /**
     * Preserves the original `fileType()` instead of reclassifying — a
     * `CodeSlicer`-elided version of a content-detected component (e.g. a
     * voter matched via `implements VoterInterface`) must not lose its type
     * just because the slicer dropped the telltale line.
     */
    public function withContent(string $content): self
    {
        return new self(
            relativePath: $this->relativePath,
            absolutePath: $this->absolutePath,
            content: $content,
            projectFileType: $this->projectFileType,
            linesCount: substr_count($content, "\n") + 1,
        );
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
        return ProjectFileType::CONTROLLER === $this->projectFileType;
    }

    public function isEntity(): bool
    {
        return ProjectFileType::ENTITY === $this->projectFileType;
    }

    public function isVoter(): bool
    {
        return ProjectFileType::VOTER === $this->projectFileType;
    }

    public function isRepository(): bool
    {
        return ProjectFileType::REPOSITORY === $this->projectFileType;
    }

    public function isForm(): bool
    {
        return ProjectFileType::FORM === $this->projectFileType;
    }

    public function isMessengerHandler(): bool
    {
        return ProjectFileType::MESSENGER_HANDLER === $this->projectFileType;
    }

    public function isAuthenticator(): bool
    {
        return ProjectFileType::AUTHENTICATOR === $this->projectFileType;
    }

    public function isEventSubscriber(): bool
    {
        return ProjectFileType::EVENT_SUBSCRIBER === $this->projectFileType;
    }

    public function isNormalizer(): bool
    {
        return ProjectFileType::NORMALIZER === $this->projectFileType;
    }

    public function isWebhookConsumer(): bool
    {
        return ProjectFileType::WEBHOOK_CONSUMER === $this->projectFileType;
    }

    public function isScheduler(): bool
    {
        return ProjectFileType::SCHEDULER === $this->projectFileType;
    }

    public function isApiResource(): bool
    {
        return ProjectFileType::API_RESOURCE === $this->projectFileType;
    }

    public function isLiveComponent(): bool
    {
        return ProjectFileType::LIVE_COMPONENT === $this->projectFileType;
    }

    public function isTwigExtension(): bool
    {
        return ProjectFileType::TWIG_EXTENSION === $this->projectFileType;
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

        if ($this->matchesMessagingComponentType()) {
            return true;
        }

        return $this->isTwigExtension();
    }

    private function matchesDomainComponentType(): bool
    {
        if ($this->isController()) {
            return true;
        }

        if ($this->isApiResource()) {
            return true;
        }

        if ($this->isLiveComponent()) {
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
        return ProjectFileType::TEMPLATE === $this->projectFileType;
    }

    public function isConfiguration(): bool
    {
        return str_ends_with($this->relativePath, '.yaml')
            || str_ends_with($this->relativePath, '.yml')
            || str_ends_with($this->relativePath, '.xml')
            || $this->isDotenvPath($this->relativePath);
    }

    private function isDotenvPath(string $path): bool
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
}
