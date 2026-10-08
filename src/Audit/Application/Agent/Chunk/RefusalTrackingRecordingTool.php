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

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\VulnerabilityCollector;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolDefinitionException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\RecordingToolInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolDefinition;

/**
 * Tells the collector about every call the wrapped recording tool refuses, so a
 * finding the model sent and the tool turned away is not mistaken for a chunk
 * with nothing to report. The model still reads the tool's own answer.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class RefusalTrackingRecordingTool implements RecordingToolInterface
{
    public function __construct(
        private RecordingToolInterface $recordingTool,
        private VulnerabilityCollector $vulnerabilityCollector,
    ) {}

    /**
     * @throws InvalidToolDefinitionException
     */
    #[Override]
    public function definition(): ToolDefinition
    {
        return $this->recordingTool->definition();
    }

    #[Override]
    public function execute(array $arguments): string
    {
        $answer = $this->recordingTool->execute($arguments);

        if (self::RECORDED !== $answer) {
            $this->vulnerabilityCollector->refuse($arguments);
        }

        return $answer;
    }
}
