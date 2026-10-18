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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunk;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;

/**
 * The fully-assembled attacker prompt for a single chunk, plus the cache key
 * and cacheability derived from the cross-iteration context, and the bytes
 * of file content the prompt carries — after code slicing, so it may be less
 * than the files hold, and the files its findings are named by. Once the
 * model answered, it also says whether that answer came at the tool-call
 * limit, where a look that found nothing is no verdict to keep.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ChunkContext
{
    /**
     * @param list<ProjectFile> $knownFiles
     */
    public function __construct(
        public string $systemPrompt,
        public string $userMessage,
        public string $contextKey,
        public bool $cacheable,
        public int $promptedFileBytes,
        public bool $reachedToolCap = false,
        public array $knownFiles = [],
    ) {}

    public function answeredBy(LLMResponse $llmResponse): self
    {
        return new self($this->systemPrompt, $this->userMessage, $this->contextKey, $this->cacheable, $this->promptedFileBytes, $llmResponse->reachedToolCap(), $this->knownFiles);
    }
}
