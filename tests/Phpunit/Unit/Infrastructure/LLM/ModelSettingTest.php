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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\LLM;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\ModelSetting;

final class ModelSettingTest extends TestCase
{
    #[DataProvider('advice')]
    public function test_it_says_where_to_set_the_model_in_the_binary_and_in_an_application(ModelSetting $modelSetting, string $expectedAdvice): void
    {
        self::assertSame($expectedAdvice, $modelSetting->advice());
    }

    /**
     * @return iterable<string, array{ModelSetting, string}>
     */
    public static function advice(): iterable
    {
        yield 'model' => [ModelSetting::Model, 'Set model: in the standalone config.yaml or run init --model=<model id>, or set symfony_security_auditor.model in a Symfony application.'];
        yield 'attacker_model' => [ModelSetting::AttackerModel, 'Set attacker_model: in the standalone config.yaml, or set symfony_security_auditor.attacker_model in a Symfony application.'];
        yield 'reviewer_model' => [ModelSetting::ReviewerModel, 'Set reviewer_model: in the standalone config.yaml or run init --reviewer-model=<model id>, or set symfony_security_auditor.reviewer_model in a Symfony application.'];
        yield 'audit.escalation.cheap_model' => [ModelSetting::CheapModel, 'Set audit.escalation.cheap_model: in the standalone config.yaml, or set symfony_security_auditor.audit.escalation.cheap_model in a Symfony application.'];
    }

    public function test_a_setting_that_holds_no_model_falls_back_to_model(): void
    {
        self::assertSame([ModelSetting::AttackerModel, ModelSetting::Model], [ModelSetting::AttackerModel->ifSet('a'), ModelSetting::AttackerModel->ifSet(null)]);
    }
}
