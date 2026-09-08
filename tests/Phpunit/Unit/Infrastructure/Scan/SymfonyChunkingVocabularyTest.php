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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Scan;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Model\ProjectFileType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\SymfonyChunkingVocabulary;

final class SymfonyChunkingVocabularyTest extends TestCase
{
    public function test_it_ranks_the_symfony_surfaces_in_attack_priority_order(): void
    {
        $chunkingVocabulary = SymfonyChunkingVocabulary::create();

        $rankedTypes = [
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
        ];

        self::assertSame(
            range(0, \count($rankedTypes) - 1),
            array_map($chunkingVocabulary->priorityOf(...), $rankedTypes),
        );
    }

    public function test_a_type_symfony_does_not_produce_ranks_behind_every_symfony_surface(): void
    {
        self::assertSame(20, SymfonyChunkingVocabulary::create()->priorityOf(ProjectFileType::ELOQUENT_MODEL));
    }

    public function test_a_controller_names_the_feature_its_files_belong_to(): void
    {
        $chunkingVocabulary = SymfonyChunkingVocabulary::create();

        self::assertSame('User', $chunkingVocabulary->featureNameOf(ProjectFileType::CONTROLLER, 'UserController'));
        self::assertSame('Invoice', $chunkingVocabulary->featureNameOf(ProjectFileType::EASYADMIN_CRUD, 'InvoiceCrudController'));
    }

    public function test_a_twig_template_matches_its_feature_without_the_template_extension(): void
    {
        self::assertSame('user.html', SymfonyChunkingVocabulary::create()->stripTemplateExtension('user.html.twig'));
    }
}
