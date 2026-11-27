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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Infrastructure\LLM;

use Override;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\CliAgentAccount;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\CliAgentBilling;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\ProcessCliAgentAccountProbe;

final class ProcessCliAgentAccountProbeTest extends TestCase
{
    private const string CLAUDE_ARGUMENTS = 'auth status --json';

    private const string CODEX_ARGUMENTS = 'login status';

    private Filesystem $filesystem;

    private string $directory;

    #[Override]
    protected function setUp(): void
    {
        $this->filesystem = new Filesystem();
        $this->directory = sys_get_temp_dir().'/ssa-cli-account-'.bin2hex(random_bytes(6));
    }

    #[Override]
    protected function tearDown(): void
    {
        $this->filesystem->remove($this->directory);
    }

    public function test_it_names_the_claude_subscription_and_account(): void
    {
        $cli = $this->fakeCli(self::CLAUDE_ARGUMENTS, '{"loggedIn":true,"authMethod":"claude.ai","apiProvider":"firstParty","email":"dev@example.com","subscriptionType":"max"}');

        self::assertEquals(CliAgentAccount::subscription('max plan, dev@example.com'), (new ProcessCliAgentAccountProbe())->probe('claudecode', $cli));
    }

    public function test_it_reports_the_api_key_claude_bills_in_place_of_the_subscription(): void
    {
        $cli = $this->fakeCli(self::CLAUDE_ARGUMENTS, '{"loggedIn":true,"authMethod":"oauth_token","apiProvider":"firstParty","apiKeySource":"ANTHROPIC_API_KEY"}');

        self::assertEquals(CliAgentAccount::apiKey('ANTHROPIC_API_KEY', 'Unset ANTHROPIC_API_KEY to run the audit on the subscription.'), (new ProcessCliAgentAccountProbe())->probe('claudecode', $cli));
    }

    public function test_an_api_key_helper_of_a_settings_file_the_audit_ignores_leaves_the_subscription_billed(): void
    {
        $cli = $this->directory.'/claude';
        $this->filesystem->dumpFile($cli, "#!/bin/sh\n[ \"\$*\" = 'auth status --json' ] || exit 64\nif [ -f \"\$CLAUDE_CONFIG_DIR/settings.json\" ] || [ -z \"\$CLAUDE_CONFIG_DIR\" ]; then echo '{\"loggedIn\":true,\"subscriptionType\":\"max\",\"apiKeySource\":\"apiKeyHelper\"}'; else echo '{\"loggedIn\":true}'; fi\n");
        $this->filesystem->chmod($cli, 0o755);

        self::assertEquals(CliAgentAccount::subscription('max plan'), (new ProcessCliAgentAccountProbe())->probe('claudecode', $cli));
    }

    public function test_it_cannot_tell_the_account_of_a_login_that_names_no_plan_besides_an_api_key_helper_the_audit_ignores(): void
    {
        $cli = $this->directory.'/claude';
        $this->filesystem->dumpFile($cli, "#!/bin/sh\nif [ -z \"\$CLAUDE_CONFIG_DIR\" ]; then echo '{\"loggedIn\":true,\"apiKeySource\":\"apiKeyHelper\"}'; else echo '{\"loggedIn\":false}'; fi\n");
        $this->filesystem->chmod($cli, 0o755);

        self::assertEquals(CliAgentAccount::unknown('"claude auth status" names no subscription plan besides an apiKeyHelper the audit ignores'), (new ProcessCliAgentAccountProbe())->probe('claudecode', $cli));
    }

    public function test_a_cli_that_is_not_logged_in_stays_so_beside_an_api_key_helper_the_audit_ignores(): void
    {
        $cli = $this->directory.'/claude';
        $this->filesystem->dumpFile($cli, "#!/bin/sh\nif [ -z \"\$CLAUDE_CONFIG_DIR\" ]; then echo '{\"loggedIn\":false,\"apiKeySource\":\"apiKeyHelper\"}'; else echo '{\"loggedIn\":false}'; fi\n");
        $this->filesystem->chmod($cli, 0o755);

        self::assertEquals(CliAgentAccount::notLoggedIn(), (new ProcessCliAgentAccountProbe())->probe('claudecode', $cli));
    }

    public function test_it_keeps_the_api_key_helper_warning_when_it_cannot_tell_where_the_helper_comes_from(): void
    {
        $cli = $this->directory.'/claude';
        $this->filesystem->dumpFile($cli, "#!/bin/sh\nif [ -z \"\$CLAUDE_CONFIG_DIR\" ]; then echo '{\"loggedIn\":true,\"apiKeySource\":\"apiKeyHelper\"}'; else echo 'not json'; fi\n");
        $this->filesystem->chmod($cli, 0o755);

        self::assertSame(CliAgentBilling::ApiKey, (new ProcessCliAgentAccountProbe())->probe('claudecode', $cli)->billing);
    }

    public function test_it_looks_for_the_helper_from_inside_an_empty_configuration_directory_only_its_user_can_open(): void
    {
        $record = $this->directory.'/second-check';
        $cli = $this->directory.'/claude';
        $this->filesystem->dumpFile($cli, \sprintf("#!/bin/sh\nif [ -n \"\$CLAUDE_CONFIG_DIR\" ]; then echo \"\$(pwd -P) \$(cd \"\$CLAUDE_CONFIG_DIR\" && pwd -P) \$(ls -A | wc -l) \$(ls -ld . | cut -c1-10)\" > %s; fi\necho '{\"loggedIn\":true,\"apiKeySource\":\"apiKeyHelper\"}'\n", escapeshellarg($record)));
        $this->filesystem->chmod($cli, 0o755);

        (new ProcessCliAgentAccountProbe())->probe('claudecode', $cli);

        [$workingDirectory, $configDirectory, $entries, $mode] = explode(' ', trim((string) file_get_contents($record)));
        self::assertSame([$configDirectory, '0', 'drwx------'], [$workingDirectory, $entries, $mode]);
    }

    #[DataProvider('statusCommands')]
    public function test_it_asks_the_cli_from_a_private_directory_rather_than_the_current_one(string $agent): void
    {
        $record = $this->directory.'/working-directory';
        $cli = $this->directory.'/cli';
        $this->filesystem->dumpFile($cli, \sprintf("#!/bin/sh\n[ -n \"\$CLAUDE_CONFIG_DIR\" ] || echo \"\$(pwd -P) \$(ls -A | wc -l) \$(ls -ld . | cut -c1-10)\" > %s\necho 'Logged in using ChatGPT'\n", escapeshellarg($record)));
        $this->filesystem->chmod($cli, 0o755);

        (new ProcessCliAgentAccountProbe())->probe($agent, $cli);

        [$workingDirectory, $entries, $mode] = explode(' ', trim((string) file_get_contents($record)));
        self::assertSame([false, '0', 'drwx------'], [(string) realpath((string) getcwd()) === $workingDirectory, $entries, $mode]);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function statusCommands(): iterable
    {
        yield 'claude auth status' => ['claudecode'];
        yield 'codex login status' => ['codex'];
    }

    public function test_it_removes_the_empty_configuration_directory_once_it_has_looked(): void
    {
        $record = $this->directory.'/config-directory';
        $cli = $this->directory.'/claude';
        $this->filesystem->dumpFile($cli, \sprintf("#!/bin/sh\nif [ -n \"\$CLAUDE_CONFIG_DIR\" ]; then echo \"\$CLAUDE_CONFIG_DIR\" > %s; fi\necho '{\"loggedIn\":true,\"apiKeySource\":\"apiKeyHelper\"}'\n", escapeshellarg($record)));
        $this->filesystem->chmod($cli, 0o755);

        (new ProcessCliAgentAccountProbe())->probe('claudecode', $cli);

        self::assertDirectoryDoesNotExist(trim((string) file_get_contents($record)));
    }

    public function test_it_names_the_managed_settings_whose_api_key_helper_bills_in_place_of_the_subscription(): void
    {
        $cli = $this->fakeCli(self::CLAUDE_ARGUMENTS, '{"loggedIn":true,"authMethod":"api_key_helper","apiKeySource":"apiKeyHelper"}');

        self::assertEquals(CliAgentAccount::apiKey('apiKeyHelper', 'Managed settings give the Claude Code CLI this apiKeyHelper: ask whoever manages them to remove it to run the audit on the subscription.'), (new ProcessCliAgentAccountProbe())->probe('claudecode', $cli));
    }

    public function test_it_points_to_claude_auth_status_for_a_key_that_is_not_an_environment_variable(): void
    {
        $cli = $this->fakeCli(self::CLAUDE_ARGUMENTS, '{"loggedIn":true,"authMethod":"api_key","apiKeySource":"/login managed key"}');

        self::assertEquals(CliAgentAccount::apiKey('/login managed key', 'Stop the Claude Code CLI using /login managed key (see "claude auth status") to run the audit on the subscription.'), (new ProcessCliAgentAccountProbe())->probe('claudecode', $cli));
    }

    public function test_it_reports_a_claude_cli_that_is_not_logged_in(): void
    {
        $cli = $this->fakeCli(self::CLAUDE_ARGUMENTS, '{"loggedIn":false,"authMethod":"none","apiProvider":"firstParty"}', 1);

        self::assertEquals(CliAgentAccount::notLoggedIn(), (new ProcessCliAgentAccountProbe())->probe('claudecode', $cli));
    }

    public function test_it_says_why_it_cannot_tell_when_the_cli_does_not_run(): void
    {
        $account = (new ProcessCliAgentAccountProbe())->probe('claudecode', $this->directory.'/missing-claude');

        self::assertEquals(CliAgentAccount::unknown(\sprintf('"%s/missing-claude auth status" failed', $this->directory)), $account);
    }

    public function test_it_says_why_it_cannot_tell_when_the_cli_answers_something_else(): void
    {
        $cli = $this->fakeCli(self::CLAUDE_ARGUMENTS, 'Usage: claude [options]');

        self::assertEquals(CliAgentAccount::unknown(\sprintf('"%s auth status" answered no status this version can read', $cli)), (new ProcessCliAgentAccountProbe())->probe('claudecode', $cli));
    }

    public function test_it_names_the_chatgpt_subscription_codex_logged_in_with(): void
    {
        $cli = $this->fakeCli(self::CODEX_ARGUMENTS, 'Logged in using ChatGPT', toStandardError: true);

        self::assertEquals(CliAgentAccount::subscription(null), (new ProcessCliAgentAccountProbe())->probe('codex', $cli));
    }

    public function test_it_reports_the_api_key_codex_logged_in_with(): void
    {
        $cli = $this->fakeCli(self::CODEX_ARGUMENTS, 'Logged in using an API key - sk-proj-***ABCD');

        self::assertEquals(CliAgentAccount::apiKey('the Codex login', 'Run "codex logout", then "codex login" with your ChatGPT account, to run the audit on the subscription.'), (new ProcessCliAgentAccountProbe())->probe('codex', $cli));
    }

    public function test_it_reports_a_codex_cli_that_is_not_logged_in(): void
    {
        $cli = $this->fakeCli(self::CODEX_ARGUMENTS, 'Not logged in', 1);

        self::assertEquals(CliAgentAccount::notLoggedIn(), (new ProcessCliAgentAccountProbe())->probe('codex', $cli));
    }

    #[RunInSeparateProcess]
    public function test_it_asks_claude_without_the_api_key_the_audit_keeps_from_it(): void
    {
        $cli = $this->directory.'/claude';
        $this->filesystem->dumpFile($cli, "#!/bin/sh\nif [ -n \"\$ANTHROPIC_API_KEY\" ]; then echo '{\"loggedIn\":true,\"apiKeySource\":\"ANTHROPIC_API_KEY\"}'; else echo '{\"loggedIn\":true}'; fi\n");
        $this->filesystem->chmod($cli, 0o755);
        putenv('ANTHROPIC_API_KEY=sk-ant-test');
        $_SERVER['ANTHROPIC_API_KEY'] = 'sk-ant-test';

        self::assertEquals(CliAgentAccount::subscription(null), (new ProcessCliAgentAccountProbe())->probe('claudecode', $cli));
    }

    public function test_it_says_why_it_cannot_tell_what_codex_answered(): void
    {
        $cli = $this->fakeCli(self::CODEX_ARGUMENTS, 'something new');

        self::assertEquals(CliAgentAccount::unknown(\sprintf('"%s login status" answered no status this version can read', $cli)), (new ProcessCliAgentAccountProbe())->probe('codex', $cli));
    }

    public function test_it_says_why_it_cannot_tell_when_codex_does_not_run(): void
    {
        $account = (new ProcessCliAgentAccountProbe())->probe('codex', $this->directory.'/missing-codex');

        self::assertEquals(CliAgentAccount::unknown(\sprintf('"%s/missing-codex login status" failed', $this->directory)), $account);
    }

    public function test_it_gives_up_on_a_cli_that_does_not_answer_in_time(): void
    {
        $cli = $this->directory.'/slow-claude';
        $this->filesystem->dumpFile($cli, "#!/bin/sh\nexec sleep 5\n");
        $this->filesystem->chmod($cli, 0o755);

        self::assertEquals(CliAgentAccount::unknown(\sprintf('"%s auth status" failed', $cli)), (new ProcessCliAgentAccountProbe(timeoutSeconds: 0.2))->probe('claudecode', $cli));
    }

    public function test_an_api_key_source_of_none_leaves_the_subscription_billed(): void
    {
        $cli = $this->fakeCli(self::CLAUDE_ARGUMENTS, '{"loggedIn":true,"authMethod":"claude.ai","apiKeySource":"none"}');

        self::assertEquals(CliAgentAccount::subscription(null), (new ProcessCliAgentAccountProbe())->probe('claudecode', $cli));
    }

    public function test_it_reads_no_status_from_json_that_is_not_an_object(): void
    {
        $cli = $this->fakeCli(self::CLAUDE_ARGUMENTS, '42');

        self::assertEquals(CliAgentAccount::unknown(\sprintf('"%s auth status" answered no status this version can read', $cli)), (new ProcessCliAgentAccountProbe())->probe('claudecode', $cli));
    }

    public function test_it_gives_up_on_a_codex_cli_that_does_not_answer_in_time(): void
    {
        $cli = $this->directory.'/slow-codex';
        $this->filesystem->dumpFile($cli, "#!/bin/sh\nexec sleep 5\n");
        $this->filesystem->chmod($cli, 0o755);

        self::assertEquals(CliAgentAccount::unknown(\sprintf('"%s login status" failed', $cli)), (new ProcessCliAgentAccountProbe(timeoutSeconds: 0.2))->probe('codex', $cli));
    }

    public function test_it_cannot_tell_the_account_of_a_provider_without_a_subscription_cli(): void
    {
        self::assertEquals(CliAgentAccount::unknown('no subscription CLI is named anthropic'), (new ProcessCliAgentAccountProbe())->probe('anthropic', null));
    }

    private function fakeCli(string $arguments, string $output, int $exitCode = 0, bool $toStandardError = false): string
    {
        $cli = $this->directory.'/cli';
        $this->filesystem->dumpFile($cli, \sprintf("#!/bin/sh\n[ \"\$*\" = '%s' ] || exit 64\ncat <<'OUT'%s\n%s\nOUT\nexit %d\n", $arguments, $toStandardError ? ' >&2' : '', $output, $exitCode));
        $this->filesystem->chmod($cli, 0o755);

        return $cli;
    }
}
