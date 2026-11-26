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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\LLM\WorkloadIdentity;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\WorkloadIdentity\WorkloadIdentityFederation;

final class WorkloadIdentityFederationTest extends TestCase
{
    public function test_it_reads_the_federation_rule_from_the_variables_the_anthropic_sdk_reads(): void
    {
        self::assertEquals(
            new WorkloadIdentityFederation('fdrl_rule', 'org-uuid', 'svac_account', 'wrkspc_space'),
            WorkloadIdentityFederation::fromEnvironment([
                'ANTHROPIC_FEDERATION_RULE_ID' => 'fdrl_rule',
                'ANTHROPIC_ORGANIZATION_ID' => 'org-uuid',
                'ANTHROPIC_SERVICE_ACCOUNT_ID' => 'svac_account',
                'ANTHROPIC_WORKSPACE_ID' => 'wrkspc_space',
            ]),
        );
    }

    public function test_it_names_the_credential_by_its_rule_and_never_by_a_token(): void
    {
        self::assertSame('workload identity federation (rule fdrl_rule)', (new WorkloadIdentityFederation('fdrl_rule', 'org-uuid'))->credentialName());
    }

    public function test_a_service_account_or_workspace_left_empty_is_not_named(): void
    {
        self::assertEquals(
            new WorkloadIdentityFederation('fdrl_rule', 'org-uuid'),
            WorkloadIdentityFederation::fromEnvironment(['ANTHROPIC_FEDERATION_RULE_ID' => 'fdrl_rule', 'ANTHROPIC_ORGANIZATION_ID' => 'org-uuid', 'ANTHROPIC_WORKSPACE_ID' => '']),
        );
    }

    /**
     * @param array<string, string> $environment
     */
    #[DataProvider('environmentsWithoutARule')]
    public function test_there_is_no_federation_without_both_a_rule_and_an_organization(array $environment): void
    {
        self::assertNull(WorkloadIdentityFederation::fromEnvironment($environment));
    }

    /**
     * @return iterable<string, array{array<string, string>}>
     */
    public static function environmentsWithoutARule(): iterable
    {
        yield 'nothing set' => [[]];
        yield 'no organization' => [['ANTHROPIC_FEDERATION_RULE_ID' => 'fdrl_rule']];
        yield 'no rule' => [['ANTHROPIC_ORGANIZATION_ID' => 'org-uuid']];
        yield 'empty rule' => [['ANTHROPIC_FEDERATION_RULE_ID' => '', 'ANTHROPIC_ORGANIZATION_ID' => 'org-uuid']];
        yield 'empty organization' => [['ANTHROPIC_FEDERATION_RULE_ID' => 'fdrl_rule', 'ANTHROPIC_ORGANIZATION_ID' => '']];
    }
}
