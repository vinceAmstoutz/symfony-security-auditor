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

use InvalidArgumentException;
use Iterator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;

final class ProjectFileTest extends TestCase
{
    public static function fileTypeProvider(): Iterator
    {
        yield ['src/Controller/UserController.php', 'controller', 'isController'];
        yield ['src/Entity/User.php', 'entity', 'isEntity'];
        yield ['src/Security/UserVoter.php', 'voter', 'isVoter'];
        yield ['src/Repository/UserRepository.php', 'repository', 'isRepository'];
    }

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

    public function test_it_throws_on_empty_relative_path(): void
    {
        $this->expectException(InvalidArgumentException::class);
        ProjectFile::create(relativePath: '  ', absolutePath: '/app/file.php', content: '<?php');
    }

    #[DataProvider('fileTypeProvider')]
    public function test_it_detects_file_types_correctly(
        string $path,
        string $expectedType,
        string $checkerMethod,
    ): void {
        $projectFile = ProjectFile::create($path, '/app/'.$path, '<?php');
        self::assertSame($expectedType, $projectFile->type());
        self::assertTrue($projectFile->{$checkerMethod}());
    }

    public function test_it_detects_form_files(): void
    {
        $projectFile = ProjectFile::create('src/Form/UserType.php', '/app/src/Form/UserType.php', '<?php');
        self::assertSame('form', $projectFile->type());
        self::assertTrue($projectFile->isForm());
    }

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

    public function test_it_detects_config_files(): void
    {
        $projectFile = ProjectFile::create('config/security.yaml', '/app/config/security.yaml', 'security:');
        self::assertSame('config', $projectFile->type());
        self::assertTrue($projectFile->isConfiguration());
    }

    public function test_it_counts_lines_correctly(): void
    {
        $content = "<?php\n\nclass Foo\n{\n    public function bar(): void {}\n}\n";
        $projectFile = ProjectFile::create('src/Foo.php', '/app/src/Foo.php', $content);
        self::assertSame(7, $projectFile->linesCount());
    }

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

    public function test_it_detects_legacy_at_isgranted_annotation_in_doc_comment(): void
    {
        $projectFile = ProjectFile::create(
            'src/Controller/LegacyController.php',
            '/app/src/Controller/LegacyController.php',
            '<?php /** @IsGranted("ROLE_ADMIN") */ class LegacyController {}',
        );

        self::assertTrue($projectFile->hasSecurityAnnotations());
    }

    public function test_it_detects_deny_access_unless_granted_call(): void
    {
        $projectFile = ProjectFile::create(
            'src/Controller/GuardedController.php',
            '/app/src/Controller/GuardedController.php',
            '<?php class GuardedController { public function action() { $this->denyAccessUnlessGranted("ROLE_USER"); } }',
        );

        self::assertTrue($projectFile->hasSecurityAnnotations());
    }

    public function test_it_detects_security_yaml_key(): void
    {
        $projectFile = ProjectFile::create(
            'config/packages/security.yaml',
            '/app/config/packages/security.yaml',
            "security:\n    providers: {}",
        );

        self::assertTrue($projectFile->hasSecurityAnnotations());
    }

    public function test_absolute_path_returns_the_absolute_path_passed_at_creation(): void
    {
        $projectFile = ProjectFile::create(
            'src/Foo.php',
            '/srv/app/src/Foo.php',
            '<?php',
        );

        self::assertSame('/srv/app/src/Foo.php', $projectFile->absolutePath());
    }

    public function test_it_detects_keyword_in_content(): void
    {
        $projectFile = ProjectFile::create('src/Repo.php', '/app/src/Repo.php', '<?php $conn->query($input);');
        self::assertTrue($projectFile->containsKeyword('$conn->query'));
        self::assertFalse($projectFile->containsKeyword('prepare'));
    }

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

    public function test_is_service_returns_true_for_plain_php_service(): void
    {
        $projectFile = ProjectFile::create('src/Service/FooService.php', '/app/src/Service/FooService.php', '<?php');
        self::assertTrue($projectFile->isService());
    }

    public function test_is_service_returns_false_for_controller(): void
    {
        $projectFile = ProjectFile::create('src/Controller/FooController.php', '/app/src/Controller/FooController.php', '<?php');
        self::assertFalse($projectFile->isService());
    }

    public function test_is_service_returns_false_for_entity(): void
    {
        $projectFile = ProjectFile::create('src/Entity/Foo.php', '/app/src/Entity/Foo.php', '<?php');
        self::assertFalse($projectFile->isService());
    }

    public function test_is_service_returns_false_for_voter(): void
    {
        $projectFile = ProjectFile::create('src/Security/FooVoter.php', '/app/src/Security/FooVoter.php', '<?php');
        self::assertFalse($projectFile->isService());
    }

    public function test_is_service_returns_false_for_repository(): void
    {
        $projectFile = ProjectFile::create('src/Repository/FooRepository.php', '/app/src/Repository/FooRepository.php', '<?php');
        self::assertFalse($projectFile->isService());
    }

    public function test_is_service_returns_false_for_form(): void
    {
        $projectFile = ProjectFile::create('src/Form/FooType.php', '/app/src/Form/FooType.php', '<?php');
        self::assertFalse($projectFile->isService());
    }

    public function test_is_service_returns_false_for_non_php_file(): void
    {
        $projectFile = ProjectFile::create('templates/foo.twig', '/app/templates/foo.twig', '{{ foo }}');
        self::assertFalse($projectFile->isService());
    }

    public function test_is_form_requires_form_directory_and_type_suffix_together(): void
    {
        $projectFile = ProjectFile::create('src/Dto/UserType.php', '/app/src/Dto/UserType.php', '<?php');
        self::assertFalse($projectFile->isForm());

        $withDirNoSuffix = ProjectFile::create('src/Form/UserHandler.php', '/app/src/Form/UserHandler.php', '<?php');
        self::assertFalse($withDirNoSuffix->isForm());
    }

    public function test_is_entity_detects_entities_directory(): void
    {
        $projectFile = ProjectFile::create('src/Entities/User.php', '/app/src/Entities/User.php', '<?php');
        self::assertTrue($projectFile->isEntity());
    }

    public function test_is_template_detects_plain_twig_extension(): void
    {
        $projectFile = ProjectFile::create('templates/foo.twig', '/app/templates/foo.twig', '{{ foo }}');
        self::assertTrue($projectFile->isTemplate());
    }

    public function test_is_configuration_detects_yml_and_xml(): void
    {
        $projectFile = ProjectFile::create('config/services.yml', '/app/config/services.yml', '');
        self::assertTrue($projectFile->isConfiguration());

        $xml = ProjectFile::create('config/services.xml', '/app/config/services.xml', '');
        self::assertTrue($xml->isConfiguration());
    }

    public function test_is_configuration_detects_yaml_extension(): void
    {
        $projectFile = ProjectFile::create('config/security.yaml', '/app/config/security.yaml', '');
        self::assertTrue($projectFile->isConfiguration());
    }

    public function test_is_configuration_returns_false_for_php_files(): void
    {
        $projectFile = ProjectFile::create('src/Service/FooService.php', '/app/src/Service/FooService.php', '<?php');
        self::assertFalse($projectFile->isConfiguration());
    }

    public function test_type_is_config_for_yaml_extension(): void
    {
        $projectFile = ProjectFile::create('config/security.yaml', '/app/config/security.yaml', '');
        self::assertSame('config', $projectFile->type());
    }

    public function test_type_is_config_for_yml_extension(): void
    {
        $projectFile = ProjectFile::create('config/services.yml', '/app/config/services.yml', '');
        self::assertSame('config', $projectFile->type());
    }

    public function test_type_is_php_for_plain_php_service_file(): void
    {
        // Tests MatchArmRemoval on the `.php` match arm in detectType().
        // If the arm is removed, a service php file would fall through to 'other'.
        $projectFile = ProjectFile::create('src/Service/FooService.php', '/app/src/Service/FooService.php', '<?php');
        self::assertSame('php', $projectFile->type());
    }

    public function test_content_hash_is_deterministic_for_identical_content(): void
    {
        $projectFile = ProjectFile::create('a.php', '/app/a.php', '<?php echo "hello";');
        $b = ProjectFile::create('b.php', '/app/b.php', '<?php echo "hello";');

        self::assertSame($projectFile->contentHash(), $b->contentHash());
    }

    public function test_content_hash_differs_for_different_content(): void
    {
        $projectFile = ProjectFile::create('a.php', '/app/a.php', '<?php echo "hello";');
        $b = ProjectFile::create('b.php', '/app/b.php', '<?php echo "world";');

        self::assertNotSame($projectFile->contentHash(), $b->contentHash());
    }

    public function test_content_hash_is_sha256_hex(): void
    {
        $projectFile = ProjectFile::create('a.php', '/app/a.php', 'x');

        self::assertSame(hash('sha256', 'x'), $projectFile->contentHash());
    }

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

    public function test_is_service_returns_false_for_authenticator(): void
    {
        $projectFile = ProjectFile::create(
            'src/Security/LoginFormAuthenticator.php',
            '/app/src/Security/LoginFormAuthenticator.php',
            '<?php',
        );

        self::assertFalse($projectFile->isService());
    }

    public function test_is_service_returns_false_for_messenger_handler(): void
    {
        $projectFile = ProjectFile::create(
            'src/Messenger/FooMessageHandler.php',
            '/app/src/Messenger/FooMessageHandler.php',
            '<?php',
        );

        self::assertFalse($projectFile->isService());
    }

    public function test_is_service_returns_false_for_event_subscriber(): void
    {
        $projectFile = ProjectFile::create(
            'src/EventSubscriber/FooSubscriber.php',
            '/app/src/EventSubscriber/FooSubscriber.php',
            '<?php',
        );

        self::assertFalse($projectFile->isService());
    }

    public function test_is_service_returns_false_for_normalizer(): void
    {
        $projectFile = ProjectFile::create(
            'src/Serializer/FooNormalizer.php',
            '/app/src/Serializer/FooNormalizer.php',
            '<?php',
        );

        self::assertFalse($projectFile->isService());
    }

    public function test_is_service_returns_false_for_webhook_consumer(): void
    {
        $projectFile = ProjectFile::create(
            'src/Webhook/FooWebhookConsumer.php',
            '/app/src/Webhook/FooWebhookConsumer.php',
            '<?php',
        );

        self::assertFalse($projectFile->isService());
    }

    public function test_is_service_returns_false_for_scheduler(): void
    {
        $projectFile = ProjectFile::create(
            'src/Schedule/FooSchedule.php',
            '/app/src/Schedule/FooSchedule.php',
            '<?php',
        );

        self::assertFalse($projectFile->isService());
    }
}
