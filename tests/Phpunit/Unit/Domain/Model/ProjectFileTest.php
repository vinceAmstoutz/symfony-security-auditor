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

use Iterator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileType;

final class ProjectFileTest extends TestCase
{
    /**
     * @throws InvalidProjectFileException
     */
    public function test_file_type_returns_the_matching_enum_case(): void
    {
        $projectFile = ProjectFile::create(
            'src/Controller/UserController.php',
            '/app/src/Controller/UserController.php',
            '<?php',
        );

        self::assertSame(ProjectFileType::CONTROLLER, $projectFile->fileType());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_file_type_falls_back_to_other_for_unrecognized_paths(): void
    {
        $projectFile = ProjectFile::create('README.md', '/app/README.md', '# Docs');

        self::assertSame(ProjectFileType::OTHER, $projectFile->fileType());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_type_string_mirrors_the_file_type_enum_value(): void
    {
        $projectFile = ProjectFile::create(
            'src/Security/UserVoter.php',
            '/app/src/Security/UserVoter.php',
            '<?php',
        );

        self::assertSame($projectFile->fileType()->value, $projectFile->type());
    }

    public static function fileTypeProvider(): Iterator
    {
        yield ['src/Controller/UserController.php', 'controller', 'isController'];
        yield ['src/Entity/User.php', 'entity', 'isEntity'];
        yield ['src/Security/UserVoter.php', 'voter', 'isVoter'];
        yield ['src/Repository/UserRepository.php', 'repository', 'isRepository'];
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_creates_with_valid_data(): void
    {
        $projectFile = ProjectFile::create(
            relativePath: 'src/Controller/UserController.php',
            absolutePath: '/app/src/Controller/UserController.php',
            content: '<?php class UserController {}',
        );

        self::assertSame('src/Controller/UserController.php', $projectFile->relativePath());
        self::assertSame('controller', $projectFile->type());
        self::assertSame(1, $projectFile->linesCount());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_throws_on_empty_relative_path(): void
    {
        $this->expectException(InvalidProjectFileException::class);
        ProjectFile::create(relativePath: '  ', absolutePath: '/app/file.php', content: '<?php');
    }

    /**
     * @throws InvalidProjectFileException
     */
    #[DataProvider('fileTypeProvider')]
    public function test_it_detects_file_types_correctly(
        string $path,
        string $expectedType,
        string $checkerMethod,
    ): void {
        $projectFile = ProjectFile::create($path, '/app/'.$path, '<?php');
        self::assertSame($expectedType, $projectFile->type());

        $checkerResult = match ($checkerMethod) {
            'isController' => $projectFile->isController(),
            'isEntity' => $projectFile->isEntity(),
            'isVoter' => $projectFile->isVoter(),
            'isRepository' => $projectFile->isRepository(),
            default => self::fail(\sprintf('Unexpected checker method: %s', $checkerMethod)),
        };
        self::assertTrue($checkerResult);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_detects_controller_in_controller_directory_without_suffix(): void
    {
        $projectFile = ProjectFile::create('src/Controller/Homepage.php', '/app/src/Controller/Homepage.php', '<?php');

        self::assertSame('controller', $projectFile->type());
        self::assertTrue($projectFile->isController());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_detects_controller_by_route_attribute_outside_controller_directory(): void
    {
        $projectFile = ProjectFile::create(
            'src/Action/ShowProfile.php',
            '/app/src/Action/ShowProfile.php',
            "<?php\nfinal class ShowProfile\n{\n    #[Route('/profile')]\n    public function __invoke() {}\n}",
        );

        self::assertSame('controller', $projectFile->type());
        self::assertTrue($projectFile->isController());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_detects_controller_by_abstract_controller_parent(): void
    {
        $projectFile = ProjectFile::create(
            'src/Web/Dashboard.php',
            '/app/src/Web/Dashboard.php',
            '<?php class Dashboard extends AbstractController {}',
        );

        self::assertTrue($projectFile->isController());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_does_not_treat_non_php_in_controller_directory_as_controller(): void
    {
        $projectFile = ProjectFile::create('src/Controller/config.yaml', '/app/src/Controller/config.yaml', 'foo: bar');

        self::assertFalse($projectFile->isController());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_plain_service_without_route_signals_is_not_a_controller(): void
    {
        $projectFile = ProjectFile::create('src/Service/PaymentService.php', '/app/src/Service/PaymentService.php', '<?php class PaymentService { public function charge() {} }');

        self::assertFalse($projectFile->isController());
        self::assertTrue($projectFile->isService());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_detects_form_files(): void
    {
        $projectFile = ProjectFile::create('src/Form/UserType.php', '/app/src/Form/UserType.php', '<?php');
        self::assertSame('form', $projectFile->type());
        self::assertTrue($projectFile->isForm());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_detects_voter_by_interface_implementation_without_suffix(): void
    {
        $projectFile = ProjectFile::create(
            'src/Security/AccessPolicy.php',
            '/app/src/Security/AccessPolicy.php',
            '<?php class AccessPolicy implements VoterInterface {}',
        );

        self::assertSame('voter', $projectFile->type());
        self::assertTrue($projectFile->isVoter());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_detects_voter_in_voter_directory_without_suffix(): void
    {
        $projectFile = ProjectFile::create('src/Security/Voter/Access.php', '/app/src/Security/Voter/Access.php', '<?php');

        self::assertTrue($projectFile->isVoter());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_detects_form_type_by_abstract_type_parent_outside_form_directory(): void
    {
        $projectFile = ProjectFile::create(
            'src/Ui/RegistrationForm.php',
            '/app/src/Ui/RegistrationForm.php',
            '<?php class RegistrationForm extends AbstractType {}',
        );

        self::assertSame('form', $projectFile->type());
        self::assertTrue($projectFile->isForm());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_detects_entity_by_orm_attribute_outside_entity_directory(): void
    {
        $projectFile = ProjectFile::create(
            'src/Model/User.php',
            '/app/src/Model/User.php',
            "<?php\n#[ORM\\Entity]\nclass User {}",
        );

        self::assertSame('entity', $projectFile->type());
        self::assertTrue($projectFile->isEntity());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_detects_repository_by_service_entity_repository_parent_without_suffix(): void
    {
        $projectFile = ProjectFile::create(
            'src/Persistence/UserStore.php',
            '/app/src/Persistence/UserStore.php',
            '<?php class UserStore extends ServiceEntityRepository {}',
        );

        self::assertSame('repository', $projectFile->type());
        self::assertTrue($projectFile->isRepository());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_detects_repository_in_repository_directory_without_suffix(): void
    {
        $projectFile = ProjectFile::create('src/Repository/UserStore.php', '/app/src/Repository/UserStore.php', '<?php');

        self::assertSame('repository', $projectFile->type());
        self::assertTrue($projectFile->isRepository());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_plain_service_is_not_misdetected_as_voter_form_entity_or_repository(): void
    {
        $projectFile = ProjectFile::create('src/Service/Mailer.php', '/app/src/Service/Mailer.php', '<?php class Mailer { public function send() {} }');

        self::assertFalse($projectFile->isVoter());
        self::assertFalse($projectFile->isForm());
        self::assertFalse($projectFile->isEntity());
        self::assertFalse($projectFile->isRepository());
        self::assertTrue($projectFile->isService());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_detects_template_files(): void
    {
        $projectFile = ProjectFile::create(
            'templates/user/index.html.twig',
            '/app/templates/user/index.html.twig',
            '{{ user.name }}',
        );
        self::assertSame('template', $projectFile->type());
        self::assertTrue($projectFile->isTemplate());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_detects_config_files(): void
    {
        $projectFile = ProjectFile::create('config/security.yaml', '/app/config/security.yaml', 'security:');
        self::assertSame('config', $projectFile->type());
        self::assertTrue($projectFile->isConfiguration());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_detects_dotenv_files_as_config(): void
    {
        $projectFile = ProjectFile::create('.env', '/app/.env', 'APP_ENV=prod');
        self::assertSame('config', $projectFile->type());
        self::assertTrue($projectFile->isConfiguration());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_detects_dotenv_variants_as_config(): void
    {
        $projectFile = ProjectFile::create('.env.dev', '/app/.env.dev', 'APP_ENV=dev');
        self::assertSame('config', $projectFile->type());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_compiled_dotenv_php_file_stays_php(): void
    {
        $projectFile = ProjectFile::create('.env.local.php', '/app/.env.local.php', '<?php return [];');
        self::assertSame('php', $projectFile->type());
        self::assertFalse($projectFile->isConfiguration());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_detects_api_platform_resources_by_attribute(): void
    {
        $projectFile = ProjectFile::create(
            'src/Entity/Book.php',
            '/app/src/Entity/Book.php',
            "<?php\nuse ApiPlatform\\Metadata\\ApiResource;\n#[ApiResource]\n#[ORM\\Entity]\nclass Book {}",
        );

        self::assertSame('api_resource', $projectFile->type());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_is_entity_is_false_for_an_entity_that_is_also_an_api_resource(): void
    {
        $projectFile = ProjectFile::create(
            'src/Entity/Book.php',
            '/app/src/Entity/Book.php',
            "<?php\nuse ApiPlatform\\Metadata\\ApiResource;\n#[ApiResource]\n#[ORM\\Entity]\nclass Book {}",
        );

        self::assertFalse($projectFile->isEntity());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_detects_api_platform_resources_outside_entity_directories(): void
    {
        $projectFile = ProjectFile::create(
            'src/ApiResource/Offer.php',
            '/app/src/ApiResource/Offer.php',
            "<?php\n#[ApiResource(operations: [new Get()])]\nclass Offer {}",
        );

        self::assertSame('api_resource', $projectFile->type());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_detects_standalone_operation_attributes_as_api_resources(): void
    {
        $projectFile = ProjectFile::create(
            'src/Entity/Article.php',
            '/app/src/Entity/Article.php',
            "<?php\nuse ApiPlatform\\Metadata\\GetCollection;\n#[GetCollection]\nclass Article {}",
        );

        self::assertSame('api_resource', $projectFile->type());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_detects_graphql_operation_attributes_as_api_resources(): void
    {
        $projectFile = ProjectFile::create(
            'src/ApiResource/Report.php',
            '/app/src/ApiResource/Report.php',
            "<?php\nuse ApiPlatform\\Metadata\\GraphQl\\QueryCollection;\n#[QueryCollection]\nclass Report {}",
        );

        self::assertSame('api_resource', $projectFile->type());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_non_php_file_with_api_resource_content_is_not_an_api_resource(): void
    {
        $projectFile = ProjectFile::create(
            'config/api_platform/resources.yaml',
            '/app/config/api_platform/resources.yaml',
            "# App\\Entity\\Book:\n#[ApiResource]\n",
        );

        self::assertSame('config', $projectFile->type());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_detects_live_components_by_attribute(): void
    {
        $projectFile = ProjectFile::create(
            'src/Twig/Components/SearchBar.php',
            '/app/src/Twig/Components/SearchBar.php',
            "<?php\nuse Symfony\\UX\\LiveComponent\\Attribute\\AsLiveComponent;\n#[AsLiveComponent]\nclass SearchBar {}",
        );

        self::assertSame('live_component', $projectFile->type());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_non_php_file_with_live_component_content_is_not_a_live_component(): void
    {
        $projectFile = ProjectFile::create(
            'config/packages/live_component.yaml',
            '/app/config/packages/live_component.yaml',
            "# marker #[AsLiveComponent] in a comment\n",
        );

        self::assertSame('config', $projectFile->type());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_api_platform_namespace_without_an_operation_attribute_is_not_an_api_resource(): void
    {
        $projectFile = ProjectFile::create(
            'src/State/BookProvider.php',
            '/app/src/State/BookProvider.php',
            "<?php\nuse ApiPlatform\\Metadata\\Operation;\nclass BookProvider {}",
        );

        self::assertSame('php', $projectFile->type());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_plain_twig_components_without_live_attribute_stay_php(): void
    {
        $projectFile = ProjectFile::create(
            'src/Twig/Components/Badge.php',
            '/app/src/Twig/Components/Badge.php',
            "<?php\n#[AsTwigComponent]\nclass Badge {}",
        );

        self::assertSame('php', $projectFile->type());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_detects_twig_extension_by_interface_implementation(): void
    {
        $projectFile = ProjectFile::create(
            'src/Twig/AppExtension.php',
            '/app/src/Twig/AppExtension.php',
            "<?php\nclass AppExtension implements ExtensionInterface {}",
        );

        self::assertSame('twig_extension', $projectFile->type());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_detects_twig_extension_by_abstract_extension_parent(): void
    {
        $projectFile = ProjectFile::create(
            'src/Twig/MarkdownExtension.php',
            '/app/src/Twig/MarkdownExtension.php',
            "<?php\nclass MarkdownExtension extends AbstractExtension {}",
        );

        self::assertSame('twig_extension', $projectFile->type());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_non_php_file_with_twig_extension_content_is_not_a_twig_extension(): void
    {
        $projectFile = ProjectFile::create(
            'templates/macros/extension.html.twig',
            '/app/templates/macros/extension.html.twig',
            '{# extends AbstractExtension in a comment #}',
        );

        self::assertSame('template', $projectFile->type());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_plain_service_without_twig_extension_signals_stays_php(): void
    {
        $projectFile = ProjectFile::create(
            'src/Twig/Formatter.php',
            '/app/src/Twig/Formatter.php',
            "<?php class Formatter { public function format(): string { return ''; } }",
        );

        self::assertSame('php', $projectFile->type());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_operation_attribute_without_api_platform_namespace_is_not_an_api_resource(): void
    {
        $projectFile = ProjectFile::create(
            'src/Controller/HomeController.php',
            '/app/src/Controller/HomeController.php',
            "<?php\n#[Get]\nclass HomeController {}",
        );

        self::assertSame('controller', $projectFile->type());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_plain_entities_without_api_resource_stay_entities(): void
    {
        $projectFile = ProjectFile::create(
            'src/Entity/User.php',
            '/app/src/Entity/User.php',
            "<?php\n#[ORM\\Entity]\nclass User {}",
        );

        self::assertSame('entity', $projectFile->type());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_counts_lines_correctly(): void
    {
        $content = "<?php\n\nclass Foo\n{\n    public function bar(): void {}\n}\n";
        $projectFile = ProjectFile::create('src/Foo.php', '/app/src/Foo.php', $content);
        self::assertSame(7, $projectFile->linesCount());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_with_content_preserves_the_original_file_type_even_when_the_new_content_would_classify_differently(): void
    {
        $projectFile = ProjectFile::create(
            'src/Security/AccessChecker.php',
            '/app/src/Security/AccessChecker.php',
            '<?php class AccessChecker implements VoterInterface {}',
        );
        self::assertSame(ProjectFileType::VOTER, $projectFile->fileType());

        $sliced = $projectFile->withContent('<?php // elided');

        self::assertSame(ProjectFileType::VOTER, $sliced->fileType());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_with_content_replaces_the_content_and_recomputes_line_count(): void
    {
        $projectFile = ProjectFile::create('src/Foo.php', '/app/src/Foo.php', '<?php');

        $sliced = $projectFile->withContent("<?php\n// elided\n");

        self::assertSame("<?php\n// elided\n", $sliced->content());
        self::assertSame(3, $sliced->linesCount());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_detects_security_annotations(): void
    {
        $projectFile = ProjectFile::create(
            'src/Controller/SecureController.php',
            '/app/src/Controller/SecureController.php',
            '<?php #[IsGranted("ROLE_ADMIN")] class SecureController {}',
        );
        self::assertTrue($projectFile->hasSecurityAnnotations());

        $withoutAnnotation = ProjectFile::create(
            'src/Controller/PublicController.php',
            '/app/src/Controller/PublicController.php',
            '<?php class PublicController {}',
        );
        self::assertFalse($withoutAnnotation->hasSecurityAnnotations());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_detects_legacy_at_isgranted_annotation_in_doc_comment(): void
    {
        $projectFile = ProjectFile::create(
            'src/Controller/LegacyController.php',
            '/app/src/Controller/LegacyController.php',
            '<?php /** @IsGranted("ROLE_ADMIN") */ class LegacyController {}',
        );

        self::assertTrue($projectFile->hasSecurityAnnotations());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_detects_deny_access_unless_granted_call(): void
    {
        $projectFile = ProjectFile::create(
            'src/Controller/GuardedController.php',
            '/app/src/Controller/GuardedController.php',
            '<?php class GuardedController { public function action() { $this->denyAccessUnlessGranted("ROLE_USER"); } }',
        );

        self::assertTrue($projectFile->hasSecurityAnnotations());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_detects_security_yaml_key(): void
    {
        $projectFile = ProjectFile::create(
            'config/packages/security.yaml',
            '/app/config/packages/security.yaml',
            "security:\n    providers: {}",
        );

        self::assertTrue($projectFile->hasSecurityAnnotations());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_absolute_path_returns_the_absolute_path_passed_at_creation(): void
    {
        $projectFile = ProjectFile::create(
            'src/Foo.php',
            '/srv/app/src/Foo.php',
            '<?php',
        );

        self::assertSame('/srv/app/src/Foo.php', $projectFile->absolutePath());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_detects_keyword_in_content(): void
    {
        $projectFile = ProjectFile::create('src/Repo.php', '/app/src/Repo.php', '<?php $conn->query($input);');
        self::assertTrue($projectFile->containsKeyword('$conn->query'));
        self::assertFalse($projectFile->containsKeyword('prepare'));
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_serializes_to_array(): void
    {
        $projectFile = ProjectFile::create(
            'src/Controller/UserController.php',
            '/app/src/Controller/UserController.php',
            '<?php #[IsGranted("ROLE_USER")] class UserController {}',
        );
        $array = $projectFile->toArray();

        self::assertArrayHasKey('path', $array);
        self::assertArrayHasKey('type', $array);
        self::assertArrayHasKey('lines', $array);
        self::assertArrayHasKey('is_controller', $array);
        self::assertArrayHasKey('has_security_annotations', $array);
        self::assertTrue($array['is_controller']);
        self::assertTrue($array['has_security_annotations']);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_is_service_returns_true_for_plain_php_service(): void
    {
        $projectFile = ProjectFile::create('src/Service/FooService.php', '/app/src/Service/FooService.php', '<?php');
        self::assertTrue($projectFile->isService());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_is_service_returns_false_for_controller(): void
    {
        $projectFile = ProjectFile::create('src/Controller/FooController.php', '/app/src/Controller/FooController.php', '<?php');
        self::assertFalse($projectFile->isService());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_is_service_returns_false_for_entity(): void
    {
        $projectFile = ProjectFile::create('src/Entity/Foo.php', '/app/src/Entity/Foo.php', '<?php');
        self::assertFalse($projectFile->isService());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_is_service_returns_false_for_voter(): void
    {
        $projectFile = ProjectFile::create('src/Security/FooVoter.php', '/app/src/Security/FooVoter.php', '<?php');
        self::assertFalse($projectFile->isService());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_is_service_returns_false_for_repository(): void
    {
        $projectFile = ProjectFile::create('src/Repository/FooRepository.php', '/app/src/Repository/FooRepository.php', '<?php');
        self::assertFalse($projectFile->isService());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_is_service_returns_false_for_form(): void
    {
        $projectFile = ProjectFile::create('src/Form/FooType.php', '/app/src/Form/FooType.php', '<?php');
        self::assertFalse($projectFile->isService());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_is_service_returns_false_for_non_php_file(): void
    {
        $projectFile = ProjectFile::create('templates/foo.twig', '/app/templates/foo.twig', '{{ foo }}');
        self::assertFalse($projectFile->isService());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_is_form_requires_form_directory_and_type_suffix_together(): void
    {
        $projectFile = ProjectFile::create('src/Dto/UserType.php', '/app/src/Dto/UserType.php', '<?php');
        self::assertFalse($projectFile->isForm());

        $withDirNoSuffix = ProjectFile::create('src/Form/UserHandler.php', '/app/src/Form/UserHandler.php', '<?php');
        self::assertFalse($withDirNoSuffix->isForm());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_is_entity_detects_entities_directory(): void
    {
        $projectFile = ProjectFile::create('src/Entities/User.php', '/app/src/Entities/User.php', '<?php');
        self::assertTrue($projectFile->isEntity());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_is_template_detects_plain_twig_extension(): void
    {
        $projectFile = ProjectFile::create('templates/foo.twig', '/app/templates/foo.twig', '{{ foo }}');
        self::assertTrue($projectFile->isTemplate());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_is_configuration_detects_yml_and_xml(): void
    {
        $projectFile = ProjectFile::create('config/services.yml', '/app/config/services.yml', '');
        self::assertTrue($projectFile->isConfiguration());

        $xml = ProjectFile::create('config/services.xml', '/app/config/services.xml', '');
        self::assertTrue($xml->isConfiguration());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_is_configuration_detects_yaml_extension(): void
    {
        $projectFile = ProjectFile::create('config/security.yaml', '/app/config/security.yaml', '');
        self::assertTrue($projectFile->isConfiguration());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_is_configuration_returns_false_for_php_files(): void
    {
        $projectFile = ProjectFile::create('src/Service/FooService.php', '/app/src/Service/FooService.php', '<?php');
        self::assertFalse($projectFile->isConfiguration());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_type_is_config_for_yaml_extension(): void
    {
        $projectFile = ProjectFile::create('config/security.yaml', '/app/config/security.yaml', '');
        self::assertSame('config', $projectFile->type());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_type_is_config_for_yml_extension(): void
    {
        $projectFile = ProjectFile::create('config/services.yml', '/app/config/services.yml', '');
        self::assertSame('config', $projectFile->type());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_type_is_config_for_xml_extension(): void
    {
        $projectFile = ProjectFile::create('config/services.xml', '/app/config/services.xml', '');
        self::assertSame('config', $projectFile->type());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_type_is_php_for_plain_php_service_file(): void
    {
        $projectFile = ProjectFile::create('src/Service/FooService.php', '/app/src/Service/FooService.php', '<?php');
        self::assertSame('php', $projectFile->type());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_content_hash_is_deterministic_for_identical_content(): void
    {
        $projectFile = ProjectFile::create('a.php', '/app/a.php', '<?php echo "hello";');
        $b = ProjectFile::create('b.php', '/app/b.php', '<?php echo "hello";');

        self::assertSame($projectFile->contentHash(), $b->contentHash());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_content_hash_differs_for_different_content(): void
    {
        $projectFile = ProjectFile::create('a.php', '/app/a.php', '<?php echo "hello";');
        $b = ProjectFile::create('b.php', '/app/b.php', '<?php echo "world";');

        self::assertNotSame($projectFile->contentHash(), $b->contentHash());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_content_hash_is_sha256_hex(): void
    {
        $projectFile = ProjectFile::create('a.php', '/app/a.php', 'x');

        self::assertSame(hash('sha256', 'x'), $projectFile->contentHash());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_detects_authenticator_by_suffix(): void
    {
        $projectFile = ProjectFile::create(
            'src/Security/LoginFormAuthenticator.php',
            '/app/src/Security/LoginFormAuthenticator.php',
            '<?php',
        );

        self::assertSame('authenticator', $projectFile->type());
        self::assertTrue($projectFile->isAuthenticator());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_detects_messenger_handler_by_suffix(): void
    {
        $projectFile = ProjectFile::create(
            'src/Messenger/SendInvoiceMessageHandler.php',
            '/app/src/Messenger/SendInvoiceMessageHandler.php',
            '<?php',
        );

        self::assertSame('messenger_handler', $projectFile->type());
        self::assertTrue($projectFile->isMessengerHandler());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_detects_messenger_handler_by_directory(): void
    {
        $projectFile = ProjectFile::create(
            'src/MessageHandler/SendInvoice.php',
            '/app/src/MessageHandler/SendInvoice.php',
            '<?php',
        );

        self::assertSame('messenger_handler', $projectFile->type());
        self::assertTrue($projectFile->isMessengerHandler());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_detects_webhook_consumer_by_suffix(): void
    {
        $projectFile = ProjectFile::create(
            'src/Webhook/StripeWebhookConsumer.php',
            '/app/src/Webhook/StripeWebhookConsumer.php',
            '<?php',
        );

        self::assertSame('webhook_consumer', $projectFile->type());
        self::assertTrue($projectFile->isWebhookConsumer());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_detects_webhook_parser_by_suffix(): void
    {
        $projectFile = ProjectFile::create(
            'src/Webhook/StripeWebhookParser.php',
            '/app/src/Webhook/StripeWebhookParser.php',
            '<?php',
        );

        self::assertSame('webhook_consumer', $projectFile->type());
        self::assertTrue($projectFile->isWebhookConsumer());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_detects_webhook_consumer_suffix_outside_webhook_directory(): void
    {
        $projectFile = ProjectFile::create(
            'src/Notification/StripeWebhookConsumer.php',
            '/app/src/Notification/StripeWebhookConsumer.php',
            '<?php',
        );

        self::assertSame('webhook_consumer', $projectFile->type());
        self::assertTrue($projectFile->isWebhookConsumer());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_detects_webhook_parser_suffix_outside_webhook_directory(): void
    {
        $projectFile = ProjectFile::create(
            'src/Notification/StripeWebhookParser.php',
            '/app/src/Notification/StripeWebhookParser.php',
            '<?php',
        );

        self::assertSame('webhook_consumer', $projectFile->type());
        self::assertTrue($projectFile->isWebhookConsumer());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_detects_plain_php_inside_webhook_directory(): void
    {
        $projectFile = ProjectFile::create(
            'src/Webhook/Handler.php',
            '/app/src/Webhook/Handler.php',
            '<?php',
        );

        self::assertSame('webhook_consumer', $projectFile->type());
        self::assertTrue($projectFile->isWebhookConsumer());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_non_php_inside_webhook_directory_is_not_a_webhook_consumer(): void
    {
        $projectFile = ProjectFile::create(
            'src/Webhook/config.yaml',
            '/app/src/Webhook/config.yaml',
            'foo: bar',
        );

        self::assertFalse($projectFile->isWebhookConsumer());
        self::assertSame('config', $projectFile->type());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_non_php_inside_message_handler_directory_is_not_a_messenger_handler(): void
    {
        $projectFile = ProjectFile::create(
            'src/MessageHandler/config.yaml',
            '/app/src/MessageHandler/config.yaml',
            'foo: bar',
        );

        self::assertFalse($projectFile->isMessengerHandler());
        self::assertSame('config', $projectFile->type());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_detects_event_subscriber_by_suffix(): void
    {
        $projectFile = ProjectFile::create(
            'src/EventSubscriber/AuditSubscriber.php',
            '/app/src/EventSubscriber/AuditSubscriber.php',
            '<?php',
        );

        self::assertSame('event_subscriber', $projectFile->type());
        self::assertTrue($projectFile->isEventSubscriber());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_detects_event_listener_by_suffix(): void
    {
        $projectFile = ProjectFile::create(
            'src/Listener/ResponseEventListener.php',
            '/app/src/Listener/ResponseEventListener.php',
            '<?php',
        );

        self::assertSame('event_subscriber', $projectFile->type());
        self::assertTrue($projectFile->isEventSubscriber());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_detects_normalizer_by_suffix(): void
    {
        $projectFile = ProjectFile::create(
            'src/Serializer/UserNormalizer.php',
            '/app/src/Serializer/UserNormalizer.php',
            '<?php',
        );

        self::assertSame('normalizer', $projectFile->type());
        self::assertTrue($projectFile->isNormalizer());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_detects_denormalizer_by_suffix(): void
    {
        $projectFile = ProjectFile::create(
            'src/Serializer/UserDenormalizer.php',
            '/app/src/Serializer/UserDenormalizer.php',
            '<?php',
        );

        self::assertSame('normalizer', $projectFile->type());
        self::assertTrue($projectFile->isNormalizer());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_detects_schedule_provider_by_suffix(): void
    {
        $projectFile = ProjectFile::create(
            'src/Schedule/CleanupScheduleProvider.php',
            '/app/src/Schedule/CleanupScheduleProvider.php',
            '<?php',
        );

        self::assertSame('scheduler', $projectFile->type());
        self::assertTrue($projectFile->isScheduler());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_detects_schedule_class_by_suffix(): void
    {
        $projectFile = ProjectFile::create(
            'src/Schedule/CleanupSchedule.php',
            '/app/src/Schedule/CleanupSchedule.php',
            '<?php',
        );

        self::assertSame('scheduler', $projectFile->type());
        self::assertTrue($projectFile->isScheduler());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_is_service_returns_false_for_authenticator(): void
    {
        $projectFile = ProjectFile::create(
            'src/Security/LoginFormAuthenticator.php',
            '/app/src/Security/LoginFormAuthenticator.php',
            '<?php',
        );

        self::assertFalse($projectFile->isService());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_is_service_returns_false_for_messenger_handler(): void
    {
        $projectFile = ProjectFile::create(
            'src/Messenger/FooMessageHandler.php',
            '/app/src/Messenger/FooMessageHandler.php',
            '<?php',
        );

        self::assertFalse($projectFile->isService());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_is_service_returns_false_for_event_subscriber(): void
    {
        $projectFile = ProjectFile::create(
            'src/EventSubscriber/FooSubscriber.php',
            '/app/src/EventSubscriber/FooSubscriber.php',
            '<?php',
        );

        self::assertFalse($projectFile->isService());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_is_service_returns_false_for_normalizer(): void
    {
        $projectFile = ProjectFile::create(
            'src/Serializer/FooNormalizer.php',
            '/app/src/Serializer/FooNormalizer.php',
            '<?php',
        );

        self::assertFalse($projectFile->isService());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_is_service_returns_false_for_webhook_consumer(): void
    {
        $projectFile = ProjectFile::create(
            'src/Webhook/FooWebhookConsumer.php',
            '/app/src/Webhook/FooWebhookConsumer.php',
            '<?php',
        );

        self::assertFalse($projectFile->isService());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_is_service_returns_false_for_scheduler(): void
    {
        $projectFile = ProjectFile::create(
            'src/Schedule/FooSchedule.php',
            '/app/src/Schedule/FooSchedule.php',
            '<?php',
        );

        self::assertFalse($projectFile->isService());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_is_service_returns_false_for_api_resource(): void
    {
        $projectFile = ProjectFile::create(
            'src/ApiResource/Book.php',
            '/app/src/ApiResource/Book.php',
            "<?php\n#[ApiResource]\nclass Book {}",
        );

        self::assertFalse($projectFile->isService());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_is_service_returns_false_for_live_component(): void
    {
        $projectFile = ProjectFile::create(
            'src/Twig/Components/Counter.php',
            '/app/src/Twig/Components/Counter.php',
            "<?php\n#[AsLiveComponent]\nclass Counter {}",
        );

        self::assertFalse($projectFile->isService());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_is_service_returns_false_for_twig_extension(): void
    {
        $projectFile = ProjectFile::create(
            'src/Twig/AppExtension.php',
            '/app/src/Twig/AppExtension.php',
            "<?php\nclass AppExtension extends AbstractExtension {}",
        );

        self::assertFalse($projectFile->isService());
    }
}
