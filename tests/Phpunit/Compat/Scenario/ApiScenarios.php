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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Scenario;

/**
 * The public PHP API: the Domain models read through their accessors, and
 * `RunAuditUseCase::execute()` with each of its arguments.
 */
final readonly class ApiScenarios
{
    /**
     * @return list<Scenario>
     */
    public static function all(): array
    {
        $scenario = Scenario::api('api/run-audit-use-case')->withProjectFiles(ProjectFixtures::base());

        return [
            Scenario::api('api/domain-models')->running(new Step('api:models'))->expectingDeprecations('Since vinceamstoutz/symfony-security-auditor 1.13: Vulnerability::create() is deprecated, use Vulnerability::of() instead.'),
            $scenario->running(new Step('api:run-audit')),
            $scenario->renamed('api/run-audit-use-case-scan-paths')->running(new Step('api:run-audit', ['scan-paths' => ['src/Controller']])),
            $scenario->renamed('api/run-audit-use-case-bypass-cache')->withConfig(['cache' => ['enabled' => true, 'dir' => '{workspace}/shared-cache']])->running(new Step('api:run-audit'), new Step('api:run-audit', ['bypass-cache' => true])),
            $scenario->renamed('api/run-audit-use-case-accepted-fingerprints')->running(new Step('api:run-audit', ['accepted-fingerprints' => ['SSA-A075585EE3E2']])),
            $scenario->renamed('api/run-audit-use-case-since')->withSetup(new GitCommit(), new WriteFile('project/src/Controller/NewController.php', ProjectFixtures::controller('NewController', [ProjectFixtures::finding(['type' => 'ssrf', 'severity' => 'high', 'title' => 'New file ssrf', 'confidence' => 0.9, 'line_start' => 7])])))->running(new Step('api:run-audit', ['since' => 'HEAD'])),
        ];
    }
}
