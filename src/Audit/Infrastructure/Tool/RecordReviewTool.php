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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewCollector;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolDefinition;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolInterface;

/**
 * Provider-agnostic schema-enforced collection seam for reviewer verdicts.
 * The LLM is instructed to invoke this tool once per reviewed finding instead
 * of emitting a JSON array; the platform validates each call's arguments
 * against the declared input schema before invocation, so a malformed verdict
 * (missing id, prose, wrapper objects) is structurally impossible and never
 * costs a discarded response.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class RecordReviewTool implements ToolInterface
{
    public function __construct(
        private ReviewCollector $reviewCollector,
    ) {}

    public function definition(): ToolDefinition
    {
        return new ToolDefinition(
            name: 'record_review',
            description: 'Record the verdict for exactly one reviewed finding — one call per finding. The id argument must match the finding id from the input. The platform validates each call against the schema, so malformed verdicts cannot be emitted.',
            parametersSchema: $this->buildSchema(),
        );
    }

    public function execute(array $arguments): string
    {
        $this->reviewCollector->add($arguments);

        return 'recorded';
    }

    /**
     * @return array{type: 'object', properties: array<string, array<string, mixed>>, required: list<string>, additionalProperties: false}
     */
    private function buildSchema(): array
    {
        $typeValues = array_map(
            static fn (VulnerabilityType $vulnerabilityType): string => $vulnerabilityType->value,
            VulnerabilityType::cases(),
        );

        $severityValues = array_map(
            static fn (VulnerabilitySeverity $vulnerabilitySeverity): string => $vulnerabilitySeverity->value,
            VulnerabilitySeverity::cases(),
        );

        return [
            'type' => 'object',
            'properties' => [
                'id' => [
                    'type' => 'string',
                    'maxLength' => 100,
                    'description' => 'The vulnerability id, must match the input finding.',
                ],
                'accepted' => [
                    'type' => 'boolean',
                    'description' => 'true when the finding represents a real risk; false to reject it.',
                ],
                'adjusted_severity' => [
                    'type' => 'string',
                    'enum' => $severityValues,
                    'description' => 'New severity when the scanner over- or under-stated impact; omit when unchanged.',
                ],
                'corrected_type' => [
                    'type' => 'string',
                    'enum' => $typeValues,
                    'description' => "Correct vulnerability type when the attacker mislabelled the finding; omit when the attacker's type is correct.",
                ],
                'reviewer_notes' => [
                    'type' => 'string',
                    'maxLength' => 5000,
                    'description' => 'Concise technical justification for the verdict.',
                ],
                'additional_attack_paths' => [
                    'type' => 'string',
                    'maxLength' => 5000,
                    'description' => 'Any additional exploitation paths found; omit when none.',
                ],
            ],
            'required' => ['id', 'accepted'],
            'additionalProperties' => false,
        ];
    }
}
