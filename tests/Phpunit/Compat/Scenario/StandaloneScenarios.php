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

use VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Runner\Workspace;

/**
 * The standalone binary: its user configuration and the configuration files
 * of the folder it runs in and of the audited project, the flags over them,
 * the guards on what a checkout may set, `init` (fresh and over an existing
 * file), the credential commands, its cache, and its help.
 */
final readonly class StandaloneScenarios
{
    private const string USER_CONFIG = 'home/config/symfony-security-auditor/config.yaml';

    private const string PROJECT_CONFIG = '.symfony-security-auditor.yaml';

    private const string PLATFORM = "platform:\n    generic:\n        default:\n            base_url: 'http://127.0.0.1:9'\n            api_key: '%env(COMPAT_API_KEY)%'\nmodel: 'gpt-4o'\n";

    private const array JSON = ['--format' => 'json'];

    /**
     * @return list<Scenario>
     */
    public static function all(): array
    {
        return [...self::audits(), ...self::configStack(), ...self::guards(), ...self::userConfig(), ...self::initialisations(), ...self::credentials(), ...self::misc()];
    }

    /**
     * @return list<Scenario>
     */
    private static function audits(): array
    {
        $scenarios = [];
        foreach (['console', 'executive', 'json', 'sarif', 'html', 'markdown', 'junit', 'github', 'github-comment'] as $format) {
            $scenarios[] = self::configured(\sprintf('standalone/format-%s', $format))->running(self::audit(['--format' => $format]));
        }

        return [
            ...$scenarios,
            self::configured('standalone/output-file')->running(self::audit([...self::JSON, '--output' => '{workspace}/out/report.json']))->collecting('out/report.json'),
            self::configured('standalone/output-dev-null')->running(self::audit([...self::JSON, '--output' => Workspace::NULL_DEVICE])),
            self::configured('standalone/dry-run')->running(self::audit(['--dry-run' => true])),
            self::configured('standalone/dry-run-json')->running(self::audit([...self::JSON, '--dry-run' => true])),
            self::configured('standalone/show-scanned')->running(self::audit(['--show-scanned' => true])),
            self::configured('standalone/run-alias-audit-run')->running((new Step('audit:run', ['project-path' => '{project}', ...self::JSON]))->in('{workspace}')),
            self::configured('standalone/run-inside-project')->running(new Step('audit', self::JSON)),
            self::configured('standalone/since')->withSetup(new GitCommit(), new WriteFile('project/src/Controller/NewController.php', ProjectFixtures::controller('NewController', [ProjectFixtures::finding(['type' => 'ssrf', 'severity' => 'high', 'title' => 'New file ssrf', 'confidence' => 0.9, 'line_start' => 7])])))->running(self::audit([...self::JSON, '--since' => 'HEAD'])),
            self::configured('standalone/path')->running(self::audit([...self::JSON, '--path' => ['src/Controller']])),
            self::configured('standalone/generate-baseline-and-use')
                ->running(self::audit([...self::JSON, '--generate-baseline' => '{workspace}/baseline.json']), self::audit([...self::JSON, '--baseline' => '{workspace}/baseline.json']))
                ->collecting('baseline.json'),
            self::configured('standalone/cache-written-by-release')
                ->withFiles([self::USER_CONFIG => \sprintf("%scache:\n    enabled: true\n", self::PLATFORM)])
                ->preparing(self::audit(self::JSON))
                ->keepingArtifacts('home/cache')
                ->running(self::audit(self::JSON)),
        ];
    }

    /**
     * @return list<Scenario>
     */
    private static function configStack(): array
    {
        $failOnMedium = "audit:\n    fail_on: medium\n";

        return [
            self::configured('standalone/stack-user-config-only')->running(self::audit(self::JSON)),
            self::configured('standalone/stack-user-config-gate')->withFiles([self::USER_CONFIG => \sprintf("%saudit:\n    fail_on: low\n", self::PLATFORM)])->running(self::audit(self::JSON)),
            self::configured('standalone/stack-working-directory')->withFiles([\sprintf('cwd/%s', self::PROJECT_CONFIG) => $failOnMedium])->running(self::audit(self::JSON)->in('{workspace}/cwd')),
            self::configured('standalone/stack-project-directory')->withFiles([\sprintf('project/%s', self::PROJECT_CONFIG) => $failOnMedium])->running(self::audit(self::JSON)),
            self::configured('standalone/stack-inside-project')->withFiles([\sprintf('project/%s', self::PROJECT_CONFIG) => $failOnMedium])->running(new Step('audit', self::JSON)),
            self::configured('standalone/stack-working-directory-and-project')
                ->withFiles([\sprintf('cwd/%s', self::PROJECT_CONFIG) => "audit:\n    fail_on: low\n", \sprintf('project/%s', self::PROJECT_CONFIG) => "audit:\n    fail_on: critical\n"])
                ->running(self::audit(self::JSON)->in('{workspace}/cwd')),
            self::configured('standalone/stack-flag-over-working-directory')->withFiles([\sprintf('cwd/%s', self::PROJECT_CONFIG) => $failOnMedium])->running(self::audit([...self::JSON, '--fail-on' => 'critical'])->in('{workspace}/cwd')),
            self::configured('standalone/stack-working-directory-model')->withFiles([\sprintf('cwd/%s', self::PROJECT_CONFIG) => "model: 'gpt-4o-mini'\n"])->running(self::audit(self::JSON)->in('{workspace}/cwd')),
            self::configured('standalone/stack-working-directory-scan-paths')
                ->withFiles([self::USER_CONFIG => \sprintf("%sscan:\n    included_paths: ['src']\n", self::PLATFORM), \sprintf('cwd/%s', self::PROJECT_CONFIG) => "scan:\n    included_paths: ['templates', 'config']\n"])
                ->running(self::audit(['--show-scanned' => true])->in('{workspace}/cwd')),
            self::configured('standalone/stack-working-directory-profile')->withFiles([\sprintf('cwd/%s', self::PROJECT_CONFIG) => "profile: 'fast'\n"])->running(self::audit(self::JSON)->in('{workspace}/cwd')),
        ];
    }

    /**
     * @return list<Scenario>
     */
    private static function guards(): array
    {
        $refused = [
            'cache' => "cache:\n    enabled: true\n",
            'privacy' => "privacy:\n    offline_only: true\n",
            'custom-skills' => "audit:\n    custom_skills:\n        mine: { file_type: controller, instructions: 'Look harder.' }\n",
            'secret-scrubbing' => "scan:\n    secret_scrubbing:\n        enabled: false\n",
            'custom-risk-patterns' => "scan:\n    custom_risk_patterns:\n        - { name: 'mine', pattern: '/x/', severity: 'high', description: 'd' }\n",
            'import-sarif' => "scan:\n    import_sarif: ['scan.sarif']\n",
            'platform' => "platform:\n    generic:\n        default:\n            base_url: 'http://evil.example'\n",
            'provider' => "provider: 'generic.default'\n",
            'budget-loosened' => "audit:\n    budget:\n        max_cost_usd: 50\n",
            'budget-tightened' => "audit:\n    budget:\n        max_cost_usd: 0.5\n",
            'env-placeholder' => "model: '%env(COMPAT_API_KEY)%'\n",
            'parameter-reference' => "model: '%kernel.project_dir%'\n",
            'malformed' => "audit: [unclosed\n",
            'not-a-map' => "audit: 'fast'\n",
            'hyphenated-keys' => "audit:\n    fail-on: low\n    max-iterations: 1\n",
        ];

        $scenarios = [];
        foreach ($refused as $name => $content) {
            $scenarios[] = self::configured(\sprintf('standalone/project-config-%s', $name))
                ->withFiles([self::USER_CONFIG => \sprintf("%saudit:\n    budget:\n        max_cost_usd: 1\n", self::PLATFORM), \sprintf('cwd/%s', self::PROJECT_CONFIG) => $content])
                ->running(self::audit(self::JSON)->in('{workspace}/cwd'));
        }

        return $scenarios;
    }

    /**
     * @return list<Scenario>
     */
    private static function userConfig(): array
    {
        $scenario = Scenario::standalone('standalone/user-config-missing')->withProjectFiles(ProjectFixtures::base())->withEnvironment(['COMPAT_API_KEY' => 'compat-test-key-0123456789']);

        return [
            $scenario->running(self::audit(self::JSON)),
            $scenario->renamed('standalone/user-config-missing-api-key')->withFiles([self::USER_CONFIG => self::PLATFORM])->withEnvironment(['COMPAT_API_KEY' => ''])->running(self::audit(self::JSON)),
            $scenario->renamed('standalone/user-config-malformed')->withFiles([self::USER_CONFIG => "platform: [unclosed\n"])->running(self::audit(self::JSON)),
            $scenario->renamed('standalone/user-config-unknown-key')->withFiles([self::USER_CONFIG => \sprintf("%saudit:\n    bogus: 1\n", self::PLATFORM)])->running(self::audit(self::JSON)),
            $scenario->renamed('standalone/user-config-hyphenated-keys')->withFiles([self::USER_CONFIG => \sprintf("%saudit:\n    fail-on: low\n    max-iterations: 1\n", self::PLATFORM)])->running(self::audit(self::JSON)),
            $scenario->renamed('standalone/user-config-http-timeout')->withFiles([self::USER_CONFIG => \sprintf("%shttp_timeout: 900\n", self::PLATFORM)])->running(self::audit(self::JSON)),
            $scenario->renamed('standalone/user-config-full')->withFiles([self::USER_CONFIG => \sprintf("%sscan:\n    max_file_size_kb: 256\naudit:\n    max_iterations: 1\n    min_confidence: 0.7\n    reviewer_batch_size: 5\n    excluded_types: ['ssrf']\n    budget:\n        max_tokens: 100000\nprivacy:\n    offline_only: false\n", self::PLATFORM)])->running(self::audit(self::JSON)),
            $scenario->renamed('standalone/user-config-provider-selector')->withFiles([self::USER_CONFIG => \sprintf("provider: 'generic.default'\n%s", self::PLATFORM)])->running(self::audit(self::JSON)),
            $scenario->renamed('standalone/user-config-unknown-provider')->withFiles([self::USER_CONFIG => \sprintf("provider: 'generic.other'\n%s", self::PLATFORM)])->running(self::audit(self::JSON)),
            $scenario->renamed('standalone/user-config-offline-only-remote')->withFiles([self::USER_CONFIG => "platform:\n    generic:\n        default:\n            base_url: 'https://gateway.example'\n            api_key: '%env(COMPAT_API_KEY)%'\nmodel: 'gpt-4o'\nprivacy:\n    offline_only: true\n"])->running(self::audit(self::JSON)),
            $scenario->renamed('standalone/doc-generic-gateway')
                ->withSetup(new CopyInput('1.21.0/standalone-configuration-01.yaml', self::USER_CONFIG))
                ->withEnvironment(['GATEWAY_TOKEN' => 'gateway-token-0123456789'])
                ->running(self::audit(self::JSON)),
            $scenario->renamed('standalone/doc-anthropic-without-bridge')
                ->withSetup(new CopyInput('1.21.0/standalone-configuration-03.yaml', self::USER_CONFIG))
                ->withEnvironment(['ANTHROPIC_API_KEY' => 'sk-ant-compat-0123456789'])
                ->running(self::audit(self::JSON)),
        ];
    }

    /**
     * @return list<Scenario>
     */
    private static function initialisations(): array
    {
        $scenario = Scenario::standalone('standalone/init-generic')->withProjectFiles(ProjectFixtures::base())->collecting(self::USER_CONFIG, 'home/data/symfony-security-auditor/composer.json');
        $existing = "provider: 'openai'\nplatform:\n    openai:\n        api_key: '%env(OPENAI_API_KEY)%'\nmodel: 'gpt-4.1'\naudit:\n    fail_on: high\n    budget:\n        max_cost_usd: 5\nhttp_timeout: 900\n";

        return [
            $scenario->running(self::init(['--provider' => 'generic.default', '--model' => 'gpt-4o', '--base-url' => 'http://127.0.0.1:9', '--env-var' => 'COMPAT_API_KEY'])),
            $scenario->renamed('standalone/init-openai')->running(self::init(['--provider' => 'openai', '--model' => 'gpt-4o'])),
            $scenario->renamed('standalone/init-anthropic-defaults')->running(self::init(['--provider' => 'anthropic'])),
            $scenario->renamed('standalone/init-ollama')->running(self::init(['--provider' => 'ollama', '--model' => 'llama3.2', '--endpoint' => 'http://127.0.0.1:11434'])),
            $scenario->renamed('standalone/init-generic-no-api-key')->running(self::init(['--provider' => 'generic.local', '--model' => 'gpt-4o', '--base-url' => 'http://127.0.0.1:9', '--no-api-key' => true])),
            $scenario->renamed('standalone/init-unknown-provider')->running(self::init(['--provider' => 'nope', '--model' => 'x'])),
            $scenario->renamed('standalone/init-base-url-refused')->running(self::init(['--provider' => 'openai', '--model' => 'gpt-4o', '--base-url' => 'http://127.0.0.1:9'])),
            $scenario->renamed('standalone/init-force')->withFiles([self::USER_CONFIG => $existing])->running(self::init(['--provider' => 'generic.default', '--model' => 'gpt-4o', '--base-url' => 'http://127.0.0.1:9', '--env-var' => 'COMPAT_API_KEY', '--force' => true])),
            $scenario->renamed('standalone/init-force-same-provider')->withFiles([self::USER_CONFIG => $existing])->running(self::init(['--provider' => 'openai', '--model' => 'gpt-4o', '--force' => true])),
            $scenario->renamed('standalone/init-existing-not-forced')->withFiles([self::USER_CONFIG => $existing])->running(self::init(['--provider' => 'openai', '--model' => 'gpt-4o'])),
            $scenario->renamed('standalone/init-existing-confirmed')->withFiles([self::USER_CONFIG => $existing])->running(self::init(['--provider' => 'openai', '--model' => 'gpt-4o'])->answering(['yes', ''])),
            $scenario->renamed('standalone/init-then-audit')
                ->withEnvironment(['COMPAT_API_KEY' => 'compat-test-key-0123456789'])
                ->running(self::init(['--provider' => 'generic.default', '--model' => 'gpt-4o', '--base-url' => 'http://127.0.0.1:9', '--env-var' => 'COMPAT_API_KEY']), self::audit(self::JSON)),
        ];
    }

    /**
     * @return list<Scenario>
     */
    private static function credentials(): array
    {
        $scenario = Scenario::standalone('standalone/credential-store-used')
            ->withProjectFiles(ProjectFixtures::base())
            ->withFiles([self::USER_CONFIG => self::PLATFORM, 'home/config/symfony-security-auditor/credentials.json' => '{"COMPAT_API_KEY":"stored-compat-key-0123456789"}'])
            ->withSetup(new ChangeMode('home/config/symfony-security-auditor/credentials.json', 0o600));

        return [
            $scenario->running(self::audit(self::JSON)),
            $scenario->renamed('standalone/credential-store-readable-by-others')->withSetup(new ChangeMode('home/config/symfony-security-auditor/credentials.json', 0o644))->running(self::audit(self::JSON)),
            $scenario->renamed('standalone/auth-status-stored')->running(new Step('auth:status')),
            $scenario->renamed('standalone/auth-status-environment')->withEnvironment(['COMPAT_API_KEY' => 'compat-env-key-0123456789'])->running(new Step('auth:status')),
            $scenario->renamed('standalone/auth-status-other-variable')->running(new Step('auth:status', ['--env-var' => 'OTHER_API_KEY'])),
            $scenario->renamed('standalone/auth-status-invalid-name')->running(new Step('auth:status', ['--env-var' => '1-not-a-name'])),
            $scenario->renamed('standalone/auth-remove')->running(new Step('auth:remove'), new Step('auth:status'))->collecting('home/config/symfony-security-auditor/credentials.json'),
            $scenario->renamed('standalone/auth-set-non-interactive')->running(new Step('auth:set', ['--env-var' => 'OTHER_API_KEY'])),
        ];
    }

    /**
     * @return list<Scenario>
     */
    private static function misc(): array
    {
        $configured = self::configured('standalone/list');

        return [
            $configured->running(new Step('list')),
            $configured->renamed('standalone/help-audit')->running(new Step('help', ['command_name' => 'audit'])),
            $configured->renamed('standalone/help-init')->running(new Step('help', ['command_name' => 'init'])),
            $configured->renamed('standalone/report-commands')->preparing(self::audit([...self::JSON, '--output' => '{workspace}/r1.json']))->keepingArtifacts('r1.json')
                ->running(new Step('audit:diff', ['previous-report' => '{workspace}/r1.json', 'current-report' => '{workspace}/r1.json']), new Step('audit:trend', ['reports' => ['{workspace}/r1.json', '{workspace}/r1.json']]), new Step('audit:baseline', ['report' => '{workspace}/r1.json', 'baseline' => '{workspace}/b.json'])),
        ];
    }

    private static function configured(string $name): Scenario
    {
        return Scenario::standalone($name)
            ->withProjectFiles(ProjectFixtures::base())
            ->withFiles([self::USER_CONFIG => self::PLATFORM])
            ->withEnvironment(['COMPAT_API_KEY' => 'compat-test-key-0123456789']);
    }

    /**
     * @param array<string, bool|int|string|list<string>|null> $input
     */
    private static function audit(array $input = []): Step
    {
        return (new Step('audit', ['project-path' => '{project}', ...$input]))->in('{workspace}');
    }

    /**
     * @param array<string, bool|int|string|list<string>|null> $input
     */
    private static function init(array $input): Step
    {
        return (new Step('init', $input))->in('{workspace}');
    }
}
