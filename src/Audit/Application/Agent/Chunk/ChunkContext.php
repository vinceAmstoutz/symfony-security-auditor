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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\KnownFiles;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;

/**
 * A chunk's attacker prompt with its cache key and cacheability, the bytes of
 * file content it carries after slicing and the files its findings are named
 * by. Once answered, also whether the answer came at the tool-call limit.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class ChunkContext
{
    public function __construct(
        public string $systemPrompt,
        public string $userMessage,
        public string $contextKey,
        public bool $cacheable,
        public int $promptedFileBytes,
        public bool $reachedToolCap = false,
        public KnownFiles $knownFiles = new KnownFiles(),
    ) {}

    public function answeredBy(LLMResponse $llmResponse): self
    {
        return new self($this->systemPrompt, $this->userMessage, $this->contextKey, $this->cacheable, $this->promptedFileBytes, $llmResponse->reachedToolCap(), $this->knownFiles);
    }
}
