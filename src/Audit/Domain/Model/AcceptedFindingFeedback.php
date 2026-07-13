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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model;

/**
 * One accepted (baselined) finding annotated with the maintainer's reason for
 * accepting it — the raw material of the reviewer's false-positive feedback.
 */
final readonly class AcceptedFindingFeedback
{
    public function __construct(
        public string $type,
        public string $file,
        public string $title,
        public string $reason,
    ) {}
}
