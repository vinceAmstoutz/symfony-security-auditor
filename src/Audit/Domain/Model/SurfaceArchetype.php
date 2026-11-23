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
 * The framework-neutral shape of a scanned file: what it *does* in an
 * application. {@see ProjectFileType} stays the precise taxonomy for prompts
 * and skill lookup.
 */
enum SurfaceArchetype: string
{
    /**
     * A route-guarded action surface: the files that reach the access-control
     * and form-binding maps. A file reached through a transport rather than a
     * route is an {@see self::ASYNC_HANDLER}.
     */
    case HTTP_ENTRYPOINT = 'http_entrypoint';

    /** States who may do what: the decision, not the identity. */
    case AUTHORIZATION_RULE = 'authorization_rule';

    /** Establishes or looks up an identity. */
    case AUTHENTICATION = 'authentication';

    /** Carries domain state and its invariants. */
    case DOMAIN_MODEL = 'domain_model';

    /** Builds or executes a query against a persistence layer. */
    case PERSISTENCE_QUERY = 'persistence_query';

    /** Declares which request fields may be written to what. */
    case INPUT_BINDING = 'input_binding';

    /** Carries out one business operation for its caller: a use case, interactor or command/query handler. */
    case APPLICATION_SERVICE = 'application_service';

    /** Consumes work that arrived out of band: a message, event or schedule. */
    case ASYNC_HANDLER = 'async_handler';

    /** Reacts to a framework lifecycle event. */
    case EVENT_HOOK = 'event_hook';

    /** Shapes data on its way in or out of a wire format. */
    case SERIALIZATION = 'serialization';

    /** Renders output, or extends the layer that does. */
    case TEMPLATE = 'template';

    /** Configuration rather than code. */
    case CONFIG = 'config';

    /** No distinctive security shape. */
    case OTHER = 'other';
}
