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

enum ProjectFileType: string
{
    case CONTROLLER = 'controller';
    case API_RESOURCE = 'api_resource';
    case LIVE_COMPONENT = 'live_component';
    case ENTITY = 'entity';
    case VOTER = 'voter';
    case REPOSITORY = 'repository';
    case FORM = 'form';
    case AUTHENTICATOR = 'authenticator';
    case MESSENGER_HANDLER = 'messenger_handler';
    case WEBHOOK_CONSUMER = 'webhook_consumer';
    case EVENT_SUBSCRIBER = 'event_subscriber';
    case NORMALIZER = 'normalizer';
    case SCHEDULER = 'scheduler';
    case TWIG_EXTENSION = 'twig_extension';
    case TEMPLATE = 'template';
    case CONFIG = 'config';
    case PHP = 'php';
    case OTHER = 'other';
}
