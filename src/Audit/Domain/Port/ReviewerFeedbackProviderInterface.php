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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ReviewerFeedback;

/**
 * The maintainer's false-positive feedback for the run, the baselined findings
 * with a `reason`: negative examples for the reviewer prompt, also part of the
 * reviewer cache key.
 */
interface ReviewerFeedbackProviderInterface
{
    public function feedback(): ReviewerFeedback;
}
