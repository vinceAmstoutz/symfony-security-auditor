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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture;

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\RecordReviewToolFactoryInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewCollector;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Tool\RecordReviewToolFactory;

final readonly class UnmarkedRecordReviewToolFactory implements RecordReviewToolFactoryInterface
{
    #[Override]
    public function create(ReviewCollector $reviewCollector): ToolInterface
    {
        return new UnmarkedTool((new RecordReviewToolFactory())->create($reviewCollector));
    }
}
