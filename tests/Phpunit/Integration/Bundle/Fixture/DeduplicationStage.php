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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Bundle\Fixture;

use Override;
use Symfony\Component\DependencyInjection\Attribute\AsTaggedItem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\StageInterface;

#[AsTaggedItem(priority: -100)]
final class DeduplicationStage implements StageInterface
{
    #[Override]
    public function process(AuditContext $auditContext): void {}

    #[Override]
    public function name(): string
    {
        return 'deduplication';
    }
}
