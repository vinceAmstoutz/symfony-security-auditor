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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Domain\Model;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Model\ChunkingVocabulary;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Model\ProjectFileType;

final class ChunkingVocabularyTest extends TestCase
{
    public function test_it_ranks_a_listed_surface_by_its_position(): void
    {
        $chunkingVocabulary = new ChunkingVocabulary(surfacePriority: [
            ProjectFileType::CONTROLLER,
            ProjectFileType::VOTER,
        ]);

        self::assertSame(0, $chunkingVocabulary->priorityOf(ProjectFileType::CONTROLLER));
        self::assertSame(1, $chunkingVocabulary->priorityOf(ProjectFileType::VOTER));
    }

    public function test_an_unlisted_surface_ranks_behind_every_listed_one(): void
    {
        $chunkingVocabulary = new ChunkingVocabulary(surfacePriority: [
            ProjectFileType::CONTROLLER,
            ProjectFileType::VOTER,
        ]);

        self::assertSame(2, $chunkingVocabulary->priorityOf(ProjectFileType::ENTITY));
    }

    public function test_without_any_priority_every_surface_ranks_the_same(): void
    {
        $chunkingVocabulary = new ChunkingVocabulary();

        self::assertSame(0, $chunkingVocabulary->priorityOf(ProjectFileType::CONTROLLER));
        self::assertSame(0, $chunkingVocabulary->priorityOf(ProjectFileType::OTHER));
    }

    public function test_it_drops_the_feature_suffix_registered_for_the_type(): void
    {
        $chunkingVocabulary = $this->withSuffixes();

        self::assertSame('User', $chunkingVocabulary->featureNameOf(ProjectFileType::CONTROLLER, 'UserController'));
        self::assertSame('Invoice', $chunkingVocabulary->featureNameOf(ProjectFileType::EASYADMIN_CRUD, 'InvoiceCrudController'));
    }

    public function test_it_drops_only_the_last_occurrence_of_the_suffix(): void
    {
        self::assertSame(
            'ControllerRegistry',
            $this->withSuffixes()->featureNameOf(ProjectFileType::CONTROLLER, 'ControllerRegistryController'),
        );
    }

    public function test_a_name_without_the_suffix_stays_whole(): void
    {
        self::assertSame('Dashboard', $this->withSuffixes()->featureNameOf(ProjectFileType::CONTROLLER, 'Dashboard'));
    }

    public function test_a_name_that_is_only_the_suffix_names_no_feature(): void
    {
        self::assertSame('', $this->withSuffixes()->featureNameOf(ProjectFileType::CONTROLLER, 'Controller'));
    }

    public function test_a_type_with_no_registered_suffix_keeps_its_whole_name(): void
    {
        self::assertSame('UserVoter', $this->withSuffixes()->featureNameOf(ProjectFileType::VOTER, 'UserVoter'));
    }

    public function test_it_strips_a_known_template_extension(): void
    {
        $chunkingVocabulary = new ChunkingVocabulary(templateExtensions: ['.twig', '.blade']);

        self::assertSame('index.html', $chunkingVocabulary->stripTemplateExtension('index.html.twig'));
        self::assertSame('show', $chunkingVocabulary->stripTemplateExtension('show.blade'));
    }

    public function test_it_leaves_a_name_ending_in_no_known_extension_alone(): void
    {
        $chunkingVocabulary = new ChunkingVocabulary(templateExtensions: ['.twig']);

        self::assertSame('UserController', $chunkingVocabulary->stripTemplateExtension('UserController'));
    }

    public function test_it_leaves_a_name_that_is_only_the_extension_alone(): void
    {
        $chunkingVocabulary = new ChunkingVocabulary(templateExtensions: ['.twig']);

        self::assertSame('.twig', $chunkingVocabulary->stripTemplateExtension('.twig'));
    }

    private function withSuffixes(): ChunkingVocabulary
    {
        return new ChunkingVocabulary(featureSuffixes: [
            ProjectFileType::CONTROLLER->value => 'Controller',
            ProjectFileType::EASYADMIN_CRUD->value => 'CrudController',
        ]);
    }
}
