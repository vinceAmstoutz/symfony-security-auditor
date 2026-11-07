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
        yield 'sonata admin by suffix' => ['src/Backoffice/StoreAdmin.php', "<?php\nuse Sonata\\AdminBundle\\Admin\\AbstractAdmin;", ProjectFileType::SONATA_ADMIN];
        yield 'sonata admin by directory' => ['src/Admin/StoreManager.php', "<?php\nuse Sonata\\AdminBundle\\Admin\\AbstractAdmin;", ProjectFileType::SONATA_ADMIN];
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
        yield 'authenticator by abstract base class without suffix' => ['src/Security/ApiKeyGuard.php', "<?php\nclass ApiKeyGuard extends AbstractAuthenticator {}", ProjectFileType::AUTHENTICATOR];
        yield 'authenticator by login form base class without suffix' => ['src/Identity/Infrastructure/Security/FormLogin.php', "<?php\nclass FormLogin extends AbstractLoginFormAuthenticator {}", ProjectFileType::AUTHENTICATOR];
        yield 'access token handler by interface' => ['src/Security/ApiTokenHandler.php', "<?php\nclass ApiTokenHandler implements AccessTokenHandlerInterface {}", ProjectFileType::AUTHENTICATOR];
        yield 'form by as-form-type attribute on its data class' => ['src/Account/Application/Registration.php', "<?php\n#[AsFormType]\nclass Registration {}", ProjectFileType::FORM];
        yield 'action routed outside the class by action directory and suffix' => ['src/Billing/UI/Http/Action/ShowInvoiceAction.php', "<?php\nfinal class ShowInvoiceAction { public function __invoke() {} }", ProjectFileType::CONTROLLER];
        yield 'action routed outside the class by actions directory and suffix' => ['src/Http/Actions/DeleteAccountAction.php', "<?php\nfinal class DeleteAccountAction { public function __invoke() {} }", ProjectFileType::CONTROLLER];
        yield 'a non-action class in an action directory stays plain php' => ['src/Domain/Action/ActionKind.php', "<?php\nenum ActionKind {}", ProjectFileType::PHP];
        yield 'use case by command handler suffix' => ['src/Ordering/Application/PlaceOrderCommandHandler.php', "<?php\nfinal class PlaceOrderCommandHandler {}", ProjectFileType::USE_CASE];
        yield 'use case by query handler suffix' => ['src/Ordering/Application/GetOrderQueryHandler.php', "<?php\nfinal class GetOrderQueryHandler {}", ProjectFileType::USE_CASE];
        yield 'use case by handler in a command directory' => ['src/Billing/Application/Command/CancelSubscriptionHandler.php', "<?php\nfinal class CancelSubscriptionHandler {}", ProjectFileType::USE_CASE];
        yield 'use case by handler in a query directory' => ['src/Billing/Application/Query/ListInvoicesHandler.php', "<?php\nfinal class ListInvoicesHandler {}", ProjectFileType::USE_CASE];
        yield 'a command message beside its handler stays plain php' => ['src/Billing/Application/Command/CancelSubscription.php', "<?php\nfinal class CancelSubscription {}", ProjectFileType::PHP];
        yield 'use case by use case directory' => ['src/Identity/Application/UseCase/ResetPassword.php', "<?php\nfinal class ResetPassword {}", ProjectFileType::USE_CASE];
        yield 'a non-php file in a use case directory is not a use case' => ['src/Identity/Application/UseCase/README.md', '# Use cases', ProjectFileType::OTHER];
        yield 'use case by command handler interface' => ['src/Shop/Application/Checkout.php', "<?php\nfinal class Checkout implements CommandHandlerInterface {}", ProjectFileType::USE_CASE];
        yield 'a document quoting a handler interface is not a use case' => ['docs/cqrs.md', 'final class Checkout implements CommandHandlerInterface', ProjectFileType::OTHER];
        yield 'use case by query handler interface without its suffix' => ['src/Shop/Application/CartSummary.php', "<?php\nfinal class CartSummary implements QueryHandler {}", ProjectFileType::USE_CASE];
        yield 'use case by command handler attribute' => ['src/Shop/Domain/Basket.php', "<?php\nfinal class Basket { #[CommandHandler]\npublic function add() {} }", ProjectFileType::USE_CASE];
        yield 'use case by query handler attribute' => ['src/Shop/ReadModel/BasketView.php', "<?php\nfinal class BasketView { #[QueryHandler]\npublic function show() {} }", ProjectFileType::USE_CASE];
        yield 'a command handler on the messenger bus stays a messenger handler' => ['src/Ordering/Application/PlaceOrderCommandHandler.php', "<?php\n#[AsMessageHandler]\nfinal class PlaceOrderCommandHandler {}", ProjectFileType::MESSENGER_HANDLER];
        yield 'use case by as-command-handler attribute' => ['src/Adapter/Security/SessionCleaner.php', "<?php\n#[AsCommandHandler]\nfinal class SessionCleaner {}", ProjectFileType::USE_CASE];
        yield 'use case by as-query-handler attribute' => ['src/Adapter/Security/SessionLister.php', "<?php\n#[AsQueryHandler]\nfinal class SessionLister {}", ProjectFileType::USE_CASE];
        yield 'use case by handler in a command handler directory' => ['src/Adapter/Customer/CommandHandler/DeleteCustomerHandler.php', "<?php\nfinal class DeleteCustomerHandler {}", ProjectFileType::USE_CASE];
        yield 'use case by handler in a query handler directory' => ['src/ApiBundle/QueryHandler/GetStatisticsHandler.php', "<?php\nfinal class GetStatisticsHandler {}", ProjectFileType::USE_CASE];
        yield 'a log handler outside handler directories stays plain php' => ['src/Logging/AuditLogHandler.php', "<?php\nfinal class AuditLogHandler {}", ProjectFileType::PHP];
        yield 'use case by handler in an application layer' => ['components/catalogs/back/src/Application/Handler/CreateCatalogHandler.php', "<?php\nfinal class CreateCatalogHandler {}", ProjectFileType::USE_CASE];
        yield 'use case by api platform state processor' => ['src/BookStore/Infrastructure/ApiPlatform/State/Processor/DiscountBookProcessor.php', "<?php\nuse ApiPlatform\\State\\ProcessorInterface;\nfinal class DiscountBookProcessor implements ProcessorInterface {}", ProjectFileType::USE_CASE];
        yield 'use case by api platform state provider' => ['src/State/OrderProvider.php', "<?php\nuse ApiPlatform\\State\\ProviderInterface;\nfinal class OrderProvider implements ProviderInterface {}", ProjectFileType::USE_CASE];
        yield 'a provider of another library is not an api platform state' => ['src/Translation/CatalogueProvider.php', "<?php\nuse Symfony\\Component\\Translation\\Provider\\ProviderInterface;\nfinal class CatalogueProvider implements ProviderInterface {}", ProjectFileType::PHP];
        yield 'a document quoting an api platform processor is not a use case' => ['docs/state.md', 'use ApiPlatform\\State\\ProcessorInterface; final class X implements ProcessorInterface', ProjectFileType::OTHER];
        yield 'authenticator plumbing by success handler interface' => ['src/API/Authentication/AccessTokenSuccessHandler.php', "<?php\nfinal class AccessTokenSuccessHandler implements AuthenticationSuccessHandlerInterface {}", ProjectFileType::AUTHENTICATOR];
        yield 'authenticator plumbing by failure handler interface' => ['src/Security/Http/LoginFailure.php', "<?php\nfinal class LoginFailure implements AuthenticationFailureHandlerInterface {}", ProjectFileType::AUTHENTICATOR];
        yield 'authenticator plumbing by entry point interface' => ['src/Security/Http/LoginRedirect.php', "<?php\nfinal class LoginRedirect implements AuthenticationEntryPointInterface {}", ProjectFileType::AUTHENTICATOR];
        yield 'authenticator plumbing by access denied handler interface' => ['src/Security/Http/Forbidden.php', "<?php\nfinal class Forbidden implements AccessDeniedHandlerInterface {}", ProjectFileType::AUTHENTICATOR];
        yield 'authenticator plumbing by user provider interface' => ['src/Security/Identity/TenantUsers.php', "<?php\nfinal class TenantUsers implements UserProviderInterface {}", ProjectFileType::AUTHENTICATOR];
        yield 'authenticator plumbing by user checker interface' => ['src/lib/MVC/Symfony/Security/UserChecker.php', "<?php\nfinal class UserChecker implements UserCheckerInterface {}", ProjectFileType::AUTHENTICATOR];
        yield 'a document quoting a security interface is not an authenticator' => ['docs/security.md', 'final class UserChecker implements UserCheckerInterface', ProjectFileType::OTHER];
        yield 'repository by api platform collection query extension' => ['src/Doctrine/QueryExtension/Shop/VisitorBasedExtension.php', "<?php\nfinal class VisitorBasedExtension implements QueryCollectionExtensionInterface {}", ProjectFileType::REPOSITORY];
        yield 'repository by api platform item query extension' => ['src/Doctrine/OwnedItemExtension.php', "<?php\nfinal class OwnedItemExtension implements QueryItemExtensionInterface {}", ProjectFileType::REPOSITORY];
        yield 'repository by sql query object directory' => ['src/Pim/Bundle/Query/Sql/ListAttributesUseableInProductGrid.php', "<?php\nfinal class ListAttributesUseableInProductGrid {}", ProjectFileType::REPOSITORY];
        yield 'a sql script in a sql directory is not a repository' => ['src/Pim/Resources/Sql/schema.sql', 'CREATE TABLE product (id INT);', ProjectFileType::OTHER];
        yield 'a class in an admin directory that is no sonata admin stays plain php' => ['src/Behat/Page/Admin/Product/IndexPage.php', "<?php\nfinal class IndexPage {}", ProjectFileType::PHP];
        yield 'an admin-suffixed class without sonata stays plain php' => ['src/Backoffice/StoreAdmin.php', "<?php\nfinal class StoreAdmin {}", ProjectFileType::PHP];
        yield 'a sonata service outside admin paths is not a sonata admin' => ['src/Block/StatsBlock.php', "<?php\nuse Sonata\\AdminBundle\\Admin\\Pool;\nfinal class StatsBlock {}", ProjectFileType::PHP];
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
