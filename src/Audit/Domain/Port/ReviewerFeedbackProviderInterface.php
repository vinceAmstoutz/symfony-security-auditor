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
 * Supplies the maintainer-authored false-positive feedback for the current
 * run — accepted baseline findings annotated with a `reason` — so the
 * reviewer prompt can treat them as negative examples and the reviewer cache
 * can key verdicts on the feedback they were produced under.
 */
interface ReviewerFeedbackProviderInterface
{
    public function feedback(): ReviewerFeedback;
}
