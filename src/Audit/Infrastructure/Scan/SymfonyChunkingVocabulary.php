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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ChunkingVocabulary;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileType;

/**
 * How a Symfony application groups into features: a `*Controller` names one
 * (EasyAdmin spells it `*CrudController`), its Twig templates carry an extra
 * `.twig` in front of the extension, and the surfaces are ordered by how much
 * attacker-reachable authority each one usually holds.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class SymfonyChunkingVocabulary
{
    public static function create(): ChunkingVocabulary
    {
        return new ChunkingVocabulary(
            surfacePriority: [
                ProjectFileType::CONTROLLER,
                ProjectFileType::API_RESOURCE,
                ProjectFileType::LIVE_COMPONENT,
                ProjectFileType::AUTHENTICATOR,
                ProjectFileType::LDAP_SERVICE,
                ProjectFileType::SONATA_ADMIN,
                ProjectFileType::EASYADMIN_CRUD,
                ProjectFileType::VOTER,
                ProjectFileType::WEBHOOK_CONSUMER,
                ProjectFileType::MESSENGER_HANDLER,
                ProjectFileType::EVENT_SUBSCRIBER,
                ProjectFileType::NORMALIZER,
                ProjectFileType::ENTITY,
                ProjectFileType::REPOSITORY,
                ProjectFileType::FORM,
                ProjectFileType::SCHEDULER,
                ProjectFileType::TEMPLATE,
                ProjectFileType::TWIG_EXTENSION,
                ProjectFileType::CONFIG,
                ProjectFileType::PHP,
            ],
            featureSuffixes: [
                ProjectFileType::CONTROLLER->value => 'Controller',
                ProjectFileType::EASYADMIN_CRUD->value => 'CrudController',
            ],
            templateExtensions: ['.twig'],
        );
    }
}
