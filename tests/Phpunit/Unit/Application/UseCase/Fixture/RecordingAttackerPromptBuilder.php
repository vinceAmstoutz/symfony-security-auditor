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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\UseCase\Fixture;

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AttackerPromptBuilderInterface;

/**
 * Answers fixed prompts and records the files and mapping it was asked to build them for.
 *
 * @internal scoped to the EstimateAuditCostUseCase tests
 */
final class RecordingAttackerPromptBuilder implements AttackerPromptBuilderInterface
{
    /** @var list<list<string>> */
    public array $systemPromptFiles = [];

    /** @var list<list<string>> */
    public array $userMessageFiles = [];

    /** @var list<SymfonyMapping> */
    public array $userMessageMappings = [];

    public function __construct(
        private readonly string $systemPrompt,
        private readonly string $userMessage,
    ) {}

    #[Override]
    public function buildSystemPrompt(array $files = []): string
    {
        $this->systemPromptFiles[] = $this->paths($files);

        return $this->systemPrompt;
    }

    #[Override]
    public function buildUserMessage(array $files, SymfonyMapping $symfonyMapping): string
    {
        $this->userMessageFiles[] = $this->paths($files);
        $this->userMessageMappings[] = $symfonyMapping;

        return $this->userMessage;
    }

    /**
     * @param list<ProjectFile> $files
     *
     * @return list<string>
     */
    private function paths(array $files): array
    {
        return array_map(static fn (ProjectFile $projectFile): string => $projectFile->relativePath(), $files);
    }
}
