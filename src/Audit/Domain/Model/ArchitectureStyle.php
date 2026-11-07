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
 * A way of laying out an application that moves its checks away from the
 * default Symfony controller.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
enum ArchitectureStyle: string
{
    case CQRS = 'cqrs';
    case ACTION_DOMAIN_RESPONDER = 'action_domain_responder';
    case LAYERED = 'layered';
    case BOUNDED_CONTEXTS = 'bounded_contexts';
}
