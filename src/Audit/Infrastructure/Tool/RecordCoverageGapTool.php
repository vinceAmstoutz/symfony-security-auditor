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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Tool;

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Critic\CoverageGapCollector;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolDefinitionException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\RecordingToolInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolDefinition;

/**
 * Schema-enforced collection seam for the coverage critic: the model records
 * each gap it names — the files no chunk showed together, what it suspects
 * and the attack class — through one call of this tool instead of a JSON
 * answer.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class RecordCoverageGapTool implements RecordingToolInterface
{
    public function __construct(
        private CoverageGapCollector $coverageGapCollector,
    ) {}

    /**
     * @throws InvalidToolDefinitionException
     */
    #[Override]
    public function definition(): ToolDefinition
    {
        return new ToolDefinition(
            name: 'record_coverage_gap',
            description: 'Record exactly one coverage gap — one call per gap: the project files no chunk showed together, what you suspect they let an attacker do, and the attack class. The platform validates each call against the schema.',
            parametersSchema: $this->buildSchema(),
        );
    }

    #[Override]
    public function execute(array $arguments): string
    {
        $violation = RequiredArguments::violation($this->buildSchema(), $arguments);
        if (null !== $violation) {
            return $violation;
        }

        $this->coverageGapCollector->add($arguments);

        return self::RECORDED;
    }

    /**
     * @return array{type: 'object', properties: array<string, array<string, mixed>>, required: list<string>, additionalProperties: false}
     */
    private function buildSchema(): array
    {
        return [
            'type' => 'object',
            'properties' => [
                'files' => [
                    'type' => 'array',
                    'items' => ['type' => 'string', 'maxLength' => 500],
                    'minItems' => 1,
                    'maxItems' => 10,
                    'description' => 'Project-relative paths, copied from the summary, of the files to analyze together: the entry point and the handler or sibling path it was never shown with.',
                ],
                'hypothesis' => [
                    'type' => 'string',
                    'maxLength' => 2000,
                    'description' => 'What these files may let an attacker do, in one or two sentences — a lead to confirm in the code, not a finding.',
                ],
                'attack_class' => [
                    'type' => 'string',
                    'maxLength' => 100,
                    'description' => 'The vulnerability class to look for, as a finding type such as broken_access_control or insecure_direct_object_reference.',
                ],
            ],
            'required' => ['files', 'hypothesis', 'attack_class'],
            'additionalProperties' => false,
        ];
    }
}
