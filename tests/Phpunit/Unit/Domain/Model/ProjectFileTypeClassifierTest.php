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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileTypeClassifier;

final class ProjectFileTypeClassifierTest extends TestCase
{
    #[DataProvider('classificationCases')]
    public function test_it_classifies_a_path_and_content_pair(string $path, string $content, ProjectFileType $projectFileType): void
    {
        self::assertSame($projectFileType, ProjectFileTypeClassifier::classify($path, $content));
    }

    /** @return iterable<string, array{string, string, ProjectFileType}> */
    public static function classificationCases(): iterable
    {
        yield 'controller by directory' => ['src/Controller/UserController.php', '<?php', ProjectFileType::CONTROLLER];
        yield 'api resource by attribute' => ['src/ApiResource/Offer.php', "<?php\n#[ApiResource]\nclass Offer {}", ProjectFileType::API_RESOURCE];
        yield 'live component by attribute' => ['src/Twig/Components/SearchBar.php', "<?php\n#[AsLiveComponent]\nclass SearchBar {}", ProjectFileType::LIVE_COMPONENT];
        yield 'live component extending abstract controller stays a live component' => ['src/Twig/Components/Cart.php', "<?php\n#[AsLiveComponent]\nclass Cart extends AbstractController {}", ProjectFileType::LIVE_COMPONENT];
        yield 'api resource with route attribute stays an api resource' => ['src/ApiResource/Offer.php', "<?php\n#[ApiResource]\n#[Route('/offers')]\nclass Offer {}", ProjectFileType::API_RESOURCE];
        yield 'api resource by fully qualified standalone operation attribute' => ['src/ApiResource/AdminStats.php', "<?php\nuse ApiPlatform\\Metadata;\n#[ApiPlatform\\Metadata\\GetCollection]\nclass AdminStats {}", ProjectFileType::API_RESOURCE];
        yield 'controller directory wins over api resource attribute' => ['src/Controller/OfferController.php', "<?php\n#[ApiResource]\nclass OfferController {}", ProjectFileType::CONTROLLER];
        yield 'invokable as-controller service without base class or route attribute' => ['src/Action/CheckoutAction.php', "<?php\n#[AsController]\nclass CheckoutAction { public function __invoke() {} }", ProjectFileType::CONTROLLER];
        yield 'controller by route attribute without base class' => ['src/Action/ExportAction.php', "<?php\nclass ExportAction { #[Route('/export')]\npublic function __invoke() {} }", ProjectFileType::CONTROLLER];
        yield 'entity by directory' => ['src/Entity/User.php', '<?php', ProjectFileType::ENTITY];
        yield 'voter by suffix' => ['src/Security/UserVoter.php', '<?php', ProjectFileType::VOTER];
        yield 'repository by directory' => ['src/Repository/UserRepository.php', '<?php', ProjectFileType::REPOSITORY];
        yield 'form by directory and suffix' => ['src/Form/UserType.php', '<?php', ProjectFileType::FORM];
        yield 'voter by suffix wins over a colocated entity-directory path' => ['src/Entity/Post/PostVoter.php', "<?php\nclass PostVoter extends Voter {}", ProjectFileType::VOTER];
        yield 'repository by suffix wins over a colocated entity-directory path' => ['src/Entity/PostRepository.php', "<?php\nclass PostRepository extends EntityRepository {}", ProjectFileType::REPOSITORY];
        yield 'form by suffix wins over a colocated entity-directory path' => ['src/Entity/Form/PostType.php', "<?php\nclass PostType extends AbstractType {}", ProjectFileType::FORM];
        yield 'authenticator by suffix' => ['src/Security/LoginFormAuthenticator.php', '<?php', ProjectFileType::AUTHENTICATOR];
        yield 'ldap service by suffix' => ['src/Directory/UserLdap.php', '<?php', ProjectFileType::LDAP_SERVICE];
        yield 'ldap service by directory' => ['src/Ldap/DirectoryLookup.php', '<?php', ProjectFileType::LDAP_SERVICE];
        yield 'ldap service by namespace usage without suffix or directory' => ['src/Service/DirectoryBind.php', "<?php\nuse Symfony\\Component\\Ldap\\LdapInterface;\nclass DirectoryBind {}", ProjectFileType::LDAP_SERVICE];
        yield 'importing only an ldap value object is not an ldap service' => ['src/Service/EntryMapper.php', "<?php\nuse Symfony\\Component\\Ldap\\Entry;\nclass EntryMapper {}", ProjectFileType::PHP];
        yield 'message handler using the ldap client stays a message handler' => ['src/Sync/ProvisionUser.php', "<?php\nuse Symfony\\Component\\Ldap\\Ldap;\n#[AsMessageHandler]\nclass ProvisionUser {}", ProjectFileType::MESSENGER_HANDLER];
        yield 'sonata admin by suffix' => ['src/Backoffice/StoreAdmin.php', '<?php', ProjectFileType::SONATA_ADMIN];
        yield 'sonata admin by directory' => ['src/Admin/StoreManager.php', '<?php', ProjectFileType::SONATA_ADMIN];
        yield 'sonata admin by base class without suffix or directory' => ['src/Backoffice/StoreManager.php', "<?php\nclass StoreManager extends AbstractAdmin {}", ProjectFileType::SONATA_ADMIN];
        yield 'a crud-suffixed controller without the easyadmin base class stays a controller' => ['src/Controller/Admin/ProductCrudController.php', '<?php', ProjectFileType::CONTROLLER];
        yield 'easyadmin crud by base class wins over the controller directory' => ['src/Controller/Admin/ProductCrudController.php', "<?php\nclass ProductCrudController extends AbstractCrudController {}", ProjectFileType::EASYADMIN_CRUD];
        yield 'easyadmin crud by base class without suffix' => ['src/Controller/Admin/ProductManager.php', "<?php\nclass ProductManager extends AbstractCrudController {}", ProjectFileType::EASYADMIN_CRUD];
        yield 'easyadmin crud by interface without suffix' => ['src/Controller/Admin/ProductManager.php', "<?php\nclass ProductManager implements CrudControllerInterface {}", ProjectFileType::EASYADMIN_CRUD];
        yield 'messenger handler by suffix' => ['src/Messenger/SendInvoiceMessageHandler.php', '<?php', ProjectFileType::MESSENGER_HANDLER];
        yield 'messenger handler by attribute' => ['src/Handler/ProcessPaymentAction.php', "<?php\n#[AsMessageHandler]\nclass ProcessPaymentAction {}", ProjectFileType::MESSENGER_HANDLER];
        yield 'webhook consumer by suffix' => ['src/Webhook/StripeWebhookConsumer.php', '<?php', ProjectFileType::WEBHOOK_CONSUMER];
        yield 'webhook consumer by remote event consumer interface' => ['src/RemoteEvent/StripeEventConsumer.php', "<?php\n#[AsRemoteEventConsumer(name: 'stripe')]\nclass StripeEventConsumer implements RemoteEventConsumerInterface {}", ProjectFileType::WEBHOOK_CONSUMER];
        yield 'webhook consumer by remote event consumer attribute alone' => ['src/RemoteEvent/StripeEventConsumer.php', "<?php\n#[AsRemoteEventConsumer(name: 'stripe')]\nclass StripeEventConsumer {}", ProjectFileType::WEBHOOK_CONSUMER];
        yield 'webhook consumer by request parser interface alone' => ['src/RemoteEvent/StripeRequestParser.php', "<?php\nclass StripeRequestParser implements RequestParserInterface {}", ProjectFileType::WEBHOOK_CONSUMER];
        yield 'authenticator by interface without suffix' => ['src/Security/ApiKeyGuard.php', "<?php\nclass ApiKeyGuard implements AuthenticatorInterface {}", ProjectFileType::AUTHENTICATOR];
        yield 'event subscriber by suffix' => ['src/EventSubscriber/AuditSubscriber.php', '<?php', ProjectFileType::EVENT_SUBSCRIBER];
        yield 'event subscriber by interface without suffix' => ['src/Listener/AuditListener.php', "<?php\nclass AuditListener implements EventSubscriberInterface {}", ProjectFileType::EVENT_SUBSCRIBER];
        yield 'event subscriber by attribute without suffix or interface' => ['src/EventListener/TenantListener.php', "<?php\n#[AsEventListener(event: 'kernel.request')]\nclass TenantListener {}", ProjectFileType::EVENT_SUBSCRIBER];
        yield 'normalizer by suffix' => ['src/Serializer/UserNormalizer.php', '<?php', ProjectFileType::NORMALIZER];
        yield 'normalizer by interface without suffix' => ['src/Serializer/UserTransformer.php', "<?php\nclass UserTransformer implements NormalizerInterface {}", ProjectFileType::NORMALIZER];
        yield 'normalizer by denormalizer interface without suffix' => ['src/Serializer/FlexibleInputHandler.php', "<?php\nclass FlexibleInputHandler implements DenormalizerInterface {}", ProjectFileType::NORMALIZER];
        yield 'scheduler by suffix' => ['src/Schedule/CleanupSchedule.php', '<?php', ProjectFileType::SCHEDULER];
        yield 'scheduler by interface without suffix' => ['src/Cron/JobProvider.php', "<?php\nclass JobProvider implements ScheduleProviderInterface {}", ProjectFileType::SCHEDULER];
        yield 'template by extension' => ['templates/user/index.html.twig', '{{ user.name }}', ProjectFileType::TEMPLATE];
        yield 'config by yaml extension' => ['config/security.yaml', 'security:', ProjectFileType::CONFIG];
        yield 'config by xml extension' => ['config/services.xml', '', ProjectFileType::CONFIG];
        yield 'config by dotenv path' => ['.env', 'APP_ENV=prod', ProjectFileType::CONFIG];
        yield 'plain php falls back to php' => ['src/Service/FooService.php', '<?php', ProjectFileType::PHP];
        yield 'unrecognized path falls back to other' => ['README.md', '# Docs', ProjectFileType::OTHER];
    }

    public function test_a_non_php_file_in_a_webhook_directory_is_not_forced_into_webhook_consumer(): void
    {
        $projectFileType = ProjectFileTypeClassifier::classify('src/Webhook/config.yaml', 'foo: bar');

        self::assertSame(ProjectFileType::CONFIG, $projectFileType);
    }

    public function test_a_non_php_file_in_a_message_handler_directory_is_not_forced_into_messenger_handler(): void
    {
        $projectFileType = ProjectFileTypeClassifier::classify('src/MessageHandler/config.yaml', 'foo: bar');

        self::assertSame(ProjectFileType::CONFIG, $projectFileType);
    }

    public function test_a_non_php_file_in_a_ldap_directory_is_not_forced_into_ldap_service(): void
    {
        $projectFileType = ProjectFileTypeClassifier::classify('src/Ldap/config.yaml', 'foo: bar');

        self::assertSame(ProjectFileType::CONFIG, $projectFileType);
    }

    public function test_a_non_php_file_in_an_admin_directory_is_not_forced_into_sonata_admin(): void
    {
        $projectFileType = ProjectFileTypeClassifier::classify('src/Admin/config.yaml', 'foo: bar');

        self::assertSame(ProjectFileType::CONFIG, $projectFileType);
    }
}
