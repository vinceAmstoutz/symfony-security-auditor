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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\ClaudeCodeSubscriptionCli;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\CodexSubscriptionCli;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\SubscriptionCliInterface;

final class SubscriptionCliReviewerModelTest extends TestCase
{
    #[DataProvider('subscriptions')]
    public function test_it_suggests_the_lightest_model_of_the_subscription_to_review_the_findings(SubscriptionCliInterface $subscriptionCli, string $reviewerModel): void
    {
        self::assertSame($reviewerModel, $subscriptionCli->suggestedReviewerModel());
    }

    /**
     * @return iterable<string, array{SubscriptionCliInterface, string}>
     */
    public static function subscriptions(): iterable
    {
        yield 'Claude' => [new ClaudeCodeSubscriptionCli(), 'claude-haiku-5-5'];
        yield 'ChatGPT' => [new CodexSubscriptionCli(), 'gpt-6-luna'];
    }
}
