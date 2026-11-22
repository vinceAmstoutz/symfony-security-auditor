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
    case LDAP_SERVICE = 'ldap_service';
    case SONATA_ADMIN = 'sonata_admin';
    case EASYADMIN_CRUD = 'easyadmin_crud';
    case USE_CASE = 'use_case';
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

    /**
     * The framework-neutral shape of this type. Every case maps to exactly one.
     */
    public function archetype(): SurfaceArchetype
    {
        return match ($this) {
            self::CONTROLLER, self::API_RESOURCE, self::LIVE_COMPONENT, self::EASYADMIN_CRUD => SurfaceArchetype::HTTP_ENTRYPOINT,
            self::VOTER => SurfaceArchetype::AUTHORIZATION_RULE,
            self::AUTHENTICATOR, self::LDAP_SERVICE => SurfaceArchetype::AUTHENTICATION,
            self::ENTITY => SurfaceArchetype::DOMAIN_MODEL,
            self::REPOSITORY => SurfaceArchetype::PERSISTENCE_QUERY,
            // A Sonata admin declares its own routes, yet `HTTP_ENTRYPOINT` stays reserved for route-guarded actions.
            self::FORM, self::SONATA_ADMIN => SurfaceArchetype::INPUT_BINDING,
            self::USE_CASE => SurfaceArchetype::APPLICATION_SERVICE,
            self::MESSENGER_HANDLER, self::WEBHOOK_CONSUMER, self::SCHEDULER => SurfaceArchetype::ASYNC_HANDLER,
            self::EVENT_SUBSCRIBER => SurfaceArchetype::EVENT_HOOK,
            self::NORMALIZER => SurfaceArchetype::SERIALIZATION,
            self::TEMPLATE, self::TWIG_EXTENSION => SurfaceArchetype::TEMPLATE,
            self::CONFIG => SurfaceArchetype::CONFIG,
            self::PHP, self::OTHER => SurfaceArchetype::OTHER,
        };
    }

    /**
     * Whether files of this type reach the access-control and form-binding
     * maps: a Live Component or an API resource may declare route-guarded
     * actions too.
     */
    public function isControllerLike(): bool
    {
        return SurfaceArchetype::HTTP_ENTRYPOINT === $this->archetype();
    }
}
