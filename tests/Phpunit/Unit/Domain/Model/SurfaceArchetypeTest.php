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

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SurfaceArchetype;

final class SurfaceArchetypeTest extends TestCase
{
    #[DataProvider('archetypeCases')]
    public function test_every_project_file_type_maps_onto_an_archetype(ProjectFileType $projectFileType, SurfaceArchetype $surfaceArchetype): void
    {
        self::assertSame($surfaceArchetype, $projectFileType->archetype());
    }

    /**
     * @return iterable<string, array{ProjectFileType, SurfaceArchetype}>
     */
    public static function archetypeCases(): iterable
    {
        yield 'a controller is a route-guarded entrypoint' => [ProjectFileType::CONTROLLER, SurfaceArchetype::HTTP_ENTRYPOINT];
        yield 'an API Platform resource is one too' => [ProjectFileType::API_RESOURCE, SurfaceArchetype::HTTP_ENTRYPOINT];
        yield 'a Live Component is one too' => [ProjectFileType::LIVE_COMPONENT, SurfaceArchetype::HTTP_ENTRYPOINT];
        yield 'an EasyAdmin CRUD controller is one too' => [ProjectFileType::EASYADMIN_CRUD, SurfaceArchetype::HTTP_ENTRYPOINT];

        yield 'a voter states an authorization rule' => [ProjectFileType::VOTER, SurfaceArchetype::AUTHORIZATION_RULE];

        yield 'an authenticator establishes identity' => [ProjectFileType::AUTHENTICATOR, SurfaceArchetype::AUTHENTICATION];
        yield 'an LDAP service is an identity backend' => [ProjectFileType::LDAP_SERVICE, SurfaceArchetype::AUTHENTICATION];

        yield 'an entity is a domain model' => [ProjectFileType::ENTITY, SurfaceArchetype::DOMAIN_MODEL];
        yield 'a repository queries persistence' => [ProjectFileType::REPOSITORY, SurfaceArchetype::PERSISTENCE_QUERY];

        yield 'a form binds request input' => [ProjectFileType::FORM, SurfaceArchetype::INPUT_BINDING];
        yield 'a Sonata admin binds request input too' => [ProjectFileType::SONATA_ADMIN, SurfaceArchetype::INPUT_BINDING];

        yield 'a messenger handler consumes a message' => [ProjectFileType::MESSENGER_HANDLER, SurfaceArchetype::ASYNC_HANDLER];
        yield 'a webhook consumer consumes a remote event' => [ProjectFileType::WEBHOOK_CONSUMER, SurfaceArchetype::ASYNC_HANDLER];
        yield 'a scheduler runs work out of band' => [ProjectFileType::SCHEDULER, SurfaceArchetype::ASYNC_HANDLER];

        yield 'an event subscriber hooks the framework' => [ProjectFileType::EVENT_SUBSCRIBER, SurfaceArchetype::EVENT_HOOK];
        yield 'a normalizer shapes serialized output' => [ProjectFileType::NORMALIZER, SurfaceArchetype::SERIALIZATION];

        yield 'a template is a view' => [ProjectFileType::TEMPLATE, SurfaceArchetype::TEMPLATE];
        yield 'a Twig extension extends the view layer' => [ProjectFileType::TWIG_EXTENSION, SurfaceArchetype::TEMPLATE];

        yield 'config is config' => [ProjectFileType::CONFIG, SurfaceArchetype::CONFIG];

        yield 'unclassified PHP has no distinctive shape' => [ProjectFileType::PHP, SurfaceArchetype::OTHER];
        yield 'and neither does anything else' => [ProjectFileType::OTHER, SurfaceArchetype::OTHER];
    }

    /**
     * Guards the mapping against a new `ProjectFileType` case being added
     * without a matching archetype — `archetype()` would then throw at runtime
     * on a file the classifier happily produced.
     */
    public function test_no_project_file_type_is_left_unmapped(): void
    {
        $mapped = array_map(
            static fn (array $case): string => $case[0]->value,
            iterator_to_array(self::archetypeCases()),
        );
        $all = array_map(
            static fn (ProjectFileType $projectFileType): string => $projectFileType->value,
            ProjectFileType::cases(),
        );

        self::assertSame([], array_values(array_diff($all, array_values($mapped))));
    }

    /**
     * `HTTP_ENTRYPOINT` is deliberately narrow — a route-guarded action surface,
     * which is exactly what {@see ProjectFileType::isControllerLike()} means. A
     * webhook consumer receives a request but is invoked by the webhook
     * transport rather than a route, so widening this would silently change
     * which files reach the access-control and form-binding maps.
     */
    public function test_the_http_entrypoint_archetype_is_exactly_the_controller_like_types(): void
    {
        $entrypoints = array_values(array_filter(
            ProjectFileType::cases(),
            static fn (ProjectFileType $projectFileType): bool => SurfaceArchetype::HTTP_ENTRYPOINT === $projectFileType->archetype(),
        ));
        $controllerLike = array_values(array_filter(
            ProjectFileType::cases(),
            static fn (ProjectFileType $projectFileType): bool => $projectFileType->isControllerLike(),
        ));

        self::assertSame($controllerLike, $entrypoints);
    }
}
