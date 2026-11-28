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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Prompt\Skill;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\ConfigAttackerSkill;

final class ConfigAttackerSkillTest extends TestCase
{
    public function test_it_leaves_out_only_an_application_local_credential_a_test_or_dev_environment_reads(): void
    {
        $block = (new ConfigAttackerSkill())->block();

        self::assertStringContainsString("- An application-local credential only a test or dev environment reads (under `when@test` or `when@dev`, in `config/packages/test/` or `config/packages/dev/`, in `.env.test` or `.env.dev`): the application's own secret (`APP_SECRET`, a JWT passphrase), a database, cache, queue or mailer DSN whose host is local or a placeholder (`localhost`, `127.0.0.1`, a container name such as `database`), or a user of an in-memory provider. Production never loads it; report it only when production reads the same value.", $block);
        self::assertStringNotContainsString('- A credential only a test or dev environment reads', $block);
    }

    public function test_it_flags_a_third_party_credential_wherever_it_is_committed(): void
    {
        self::assertStringContainsString('DO flag a credential a third-party service issued (a cloud provider key, a GitHub, Slack or Stripe token, an SMTP or API password of a remote service) wherever it is committed, since the commit leaks it whichever environment reads it.', (new ConfigAttackerSkill())->block());
    }

    public function test_it_judges_a_redacted_credential_by_its_variable_name_and_redaction_kind(): void
    {
        self::assertStringContainsString('A value may reach you redacted, as in `GITHUB_TOKEN=***REDACTED:env_assignment***`: judge then by the variable or key name (`AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, `STRIPE_SECRET_KEY`) and by the redaction kind when it names an issuer (`aws_access_key`, `github_token`, `stripe_key`). Flag it too when neither tells who issued the credential, as for a DSN whose host is redacted.', (new ConfigAttackerSkill())->block());
    }
}
