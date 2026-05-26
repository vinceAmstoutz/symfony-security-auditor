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
        private string $type,
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
            type: self::detectType($relativePath),
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
        return $this->type;
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
        return str_ends_with($this->relativePath, 'Controller.php');
    }

    public function isEntity(): bool
    {
        return str_contains($this->relativePath, '/Entity/')
            || str_contains($this->relativePath, '/Entities/');
    }

    public function isVoter(): bool
    {
        return str_ends_with($this->relativePath, 'Voter.php');
    }

    public function isRepository(): bool
    {
        return str_ends_with($this->relativePath, 'Repository.php');
    }

    public function isForm(): bool
    {
        return str_contains($this->relativePath, '/Form/')
            && str_ends_with($this->relativePath, 'Type.php');
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
        return !$this->isController()
            && !$this->isEntity()
            && !$this->isVoter()
            && !$this->isRepository()
            && !$this->isForm()
            && !$this->isMessengerHandler()
            && !$this->isAuthenticator()
            && !$this->isEventSubscriber()
            && !$this->isNormalizer()
            && !$this->isWebhookConsumer()
            && !$this->isScheduler()
            && str_ends_with($this->relativePath, '.php');
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
            || str_ends_with($this->relativePath, '.xml');
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
            'type' => $this->type,
            'lines' => $this->linesCount,
            'is_controller' => $this->isController(),
            'is_entity' => $this->isEntity(),
            'is_voter' => $this->isVoter(),
            'is_repository' => $this->isRepository(),
            'is_form' => $this->isForm(),
            'has_security_annotations' => $this->hasSecurityAnnotations(),
        ];
    }

    private static function detectType(string $path): string
    {
        return match (true) {
            str_ends_with($path, 'Controller.php') => 'controller',
            str_contains($path, '/Entity/') => 'entity',
            str_ends_with($path, 'Voter.php') => 'voter',
            str_ends_with($path, 'Repository.php') => 'repository',
            str_contains($path, '/Form/') => 'form',
            str_ends_with($path, 'Authenticator.php') => 'authenticator',
            str_ends_with($path, 'MessageHandler.php') || str_contains($path, '/MessageHandler/') => 'messenger_handler',
            str_ends_with($path, 'WebhookConsumer.php') || str_ends_with($path, 'WebhookParser.php') || str_contains($path, '/Webhook/') => 'webhook_consumer',
            str_ends_with($path, 'Subscriber.php') || str_ends_with($path, 'EventListener.php') => 'event_subscriber',
            str_ends_with($path, 'Normalizer.php') || str_ends_with($path, 'Denormalizer.php') => 'normalizer',
            str_ends_with($path, 'ScheduleProvider.php') || str_ends_with($path, 'Schedule.php') => 'scheduler',
            str_ends_with($path, '.twig') => 'template',
            str_ends_with($path, '.yaml') || str_ends_with($path, '.yml') => 'config',
            str_ends_with($path, '.php') => 'php',
            default => 'other',
        };
    }
}
