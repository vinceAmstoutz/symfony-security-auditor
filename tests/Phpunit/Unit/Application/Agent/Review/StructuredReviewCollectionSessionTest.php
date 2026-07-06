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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Review;

use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\StructuredReviewCollectionSession;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolRegistryException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Tool\RecordReviewToolFactory;

final class StructuredReviewCollectionSessionTest extends TestCase
{
    /**
     * @throws InvalidToolRegistryException
     */
    public function test_begin_wires_the_collector_into_a_single_record_review_tool_registry(): void
    {
        $structuredReviewCollectionSession = StructuredReviewCollectionSession::begin(new RecordReviewToolFactory(), new NullLogger());

        self::assertTrue($structuredReviewCollectionSession->toolRegistry->has('record_review'));
    }

    /**
     * @throws InvalidToolRegistryException
     */
    public function test_drain_returns_the_verdicts_recorded_through_the_tool_during_the_session(): void
    {
        $structuredReviewCollectionSession = StructuredReviewCollectionSession::begin(new RecordReviewToolFactory(), new NullLogger());

        $verdict = ['id' => 'VULN-abc123', 'accepted' => true];
        $structuredReviewCollectionSession->toolRegistry->execute('record_review', $verdict);

        self::assertSame([$verdict], $structuredReviewCollectionSession->drain());
    }

    /**
     * @throws InvalidToolRegistryException
     */
    public function test_drain_clears_the_collector_so_a_second_drain_is_empty(): void
    {
        $structuredReviewCollectionSession = StructuredReviewCollectionSession::begin(new RecordReviewToolFactory(), new NullLogger());

        $structuredReviewCollectionSession->toolRegistry->execute('record_review', ['id' => 'VULN-abc123', 'accepted' => true]);
        $structuredReviewCollectionSession->drain();

        self::assertSame([], $structuredReviewCollectionSession->drain());
    }

    /**
     * @throws InvalidToolRegistryException
     */
    public function test_two_sessions_from_the_same_factory_do_not_share_a_collector(): void
    {
        $recordReviewToolFactory = new RecordReviewToolFactory();

        $structuredReviewCollectionSession = StructuredReviewCollectionSession::begin($recordReviewToolFactory, new NullLogger());
        $second = StructuredReviewCollectionSession::begin($recordReviewToolFactory, new NullLogger());

        $structuredReviewCollectionSession->toolRegistry->execute('record_review', ['id' => 'VULN-abc123', 'accepted' => true]);

        self::assertSame([], $second->drain());
    }
}
