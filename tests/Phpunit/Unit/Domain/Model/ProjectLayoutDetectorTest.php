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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ArchitectureStyle;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectLayoutDetector;

final class ProjectLayoutDetectorTest extends TestCase
{
    /**
     * @throws InvalidProjectFileException
     */
    public function test_a_project_with_command_handlers_is_laid_out_in_cqrs(): void
    {
        $files = [ProjectFile::create('src/Ordering/Application/PlaceOrderCommandHandler.php', '/app/a', '<?php final class PlaceOrderCommandHandler {}')];

        self::assertSame([ArchitectureStyle::CQRS], ProjectLayoutDetector::stylesOf($files));
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_each_style_is_named_once_however_many_files_show_it(): void
    {
        $files = [
            ProjectFile::create('src/Ordering/Application/PlaceOrderCommandHandler.php', '/app/a', '<?php final class PlaceOrderCommandHandler {}'),
            ProjectFile::create('src/Ordering/Application/GetOrderQueryHandler.php', '/app/b', '<?php final class GetOrderQueryHandler {}'),
        ];

        self::assertSame([ArchitectureStyle::CQRS], ProjectLayoutDetector::stylesOf($files));
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_a_messenger_handler_of_a_command_marks_cqrs_too(): void
    {
        $files = [ProjectFile::create('src/Ordering/Application/PlaceOrderCommandHandler.php', '/app/a', "<?php\n#[AsMessageHandler]\nfinal class PlaceOrderCommandHandler {}")];

        self::assertSame([ArchitectureStyle::CQRS], ProjectLayoutDetector::stylesOf($files));
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_a_messenger_handler_of_a_query_marks_cqrs_too(): void
    {
        $files = [ProjectFile::create('src/Ordering/Application/GetOrderQueryHandler.php', '/app/a', "<?php\n#[AsMessageHandler]\nfinal class GetOrderQueryHandler {}")];

        self::assertSame([ArchitectureStyle::CQRS], ProjectLayoutDetector::stylesOf($files));
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_a_default_layout_with_a_plain_message_handler_shows_no_style(): void
    {
        $files = [
            ProjectFile::create('src/Controller/InvoiceController.php', '/app/a', '<?php final class InvoiceController {}'),
            ProjectFile::create('src/MessageHandler/SendInvoiceMessageHandler.php', '/app/b', "<?php\n#[AsMessageHandler]\nfinal class SendInvoiceMessageHandler {}"),
        ];

        self::assertSame([], ProjectLayoutDetector::stylesOf($files));
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_single_action_classes_mark_action_domain_responder(): void
    {
        $files = [ProjectFile::create('src/Billing/UI/Http/Action/ShowInvoiceAction.php', '/app/a', '<?php final class ShowInvoiceAction {}')];

        self::assertSame([ArchitectureStyle::ACTION_DOMAIN_RESPONDER], ProjectLayoutDetector::stylesOf($files));
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_single_action_classes_in_an_actions_folder_mark_action_domain_responder(): void
    {
        $files = [ProjectFile::create('src/Http/Actions/DeleteAccountAction.php', '/app/a', '<?php final class DeleteAccountAction {}')];

        self::assertSame([ArchitectureStyle::ACTION_DOMAIN_RESPONDER], ProjectLayoutDetector::stylesOf($files));
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_a_message_handler_named_like_an_action_is_no_single_action_class(): void
    {
        $files = [ProjectFile::create('src/Action/ProcessPaymentAction.php', '/app/a', "<?php\n#[AsMessageHandler]\nfinal class ProcessPaymentAction {}")];

        self::assertSame([], ProjectLayoutDetector::stylesOf($files));
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_domain_application_and_infrastructure_layers_mark_a_layered_architecture(): void
    {
        $files = [
            ProjectFile::create('src/Domain/Order.php', '/app/a', '<?php final class Order {}'),
            ProjectFile::create('src/Application/OrderService.php', '/app/b', '<?php final class OrderService {}'),
            ProjectFile::create('src/Infrastructure/DoctrineOrders.php', '/app/c', '<?php final class DoctrineOrders {}'),
        ];

        self::assertSame([ArchitectureStyle::LAYERED], ProjectLayoutDetector::stylesOf($files));
    }

    /**
     * @param list<string> $paths
     *
     * @throws InvalidProjectFileException
     */
    #[DataProvider('twoLayersOutOfThree')]
    public function test_two_layers_out_of_three_are_no_layered_architecture(array $paths): void
    {
        $files = array_map(static fn (string $path): ProjectFile => ProjectFile::create($path, '/app/'.$path, '<?php'), $paths);

        self::assertSame([], ProjectLayoutDetector::stylesOf($files));
    }

    /**
     * @return iterable<string, array{list<string>}>
     */
    public static function twoLayersOutOfThree(): iterable
    {
        yield 'no domain layer' => [['src/Application/OrderService.php', 'src/Infrastructure/DoctrineOrders.php']];
        yield 'no application layer' => [['src/Domain/Order.php', 'src/Infrastructure/DoctrineOrders.php']];
        yield 'no infrastructure layer' => [['src/Domain/Order.php', 'src/Application/OrderService.php']];
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_modules_with_a_domain_of_their_own_mark_bounded_contexts(): void
    {
        $files = [
            ProjectFile::create('src/Billing/Domain/Invoice.php', '/app/a', '<?php final class Invoice {}'),
            ProjectFile::create('src/Identity/Domain/User.php', '/app/b', '<?php final class User {}'),
        ];

        self::assertSame([ArchitectureStyle::BOUNDED_CONTEXTS], ProjectLayoutDetector::stylesOf($files));
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_the_source_root_holding_a_domain_layer_is_no_bounded_context(): void
    {
        $files = [
            ProjectFile::create('src/Domain/Order.php', '/app/a', '<?php final class Order {}'),
            ProjectFile::create('src/Billing/Domain/Invoice.php', '/app/b', '<?php final class Invoice {}'),
        ];

        self::assertSame(['Billing'], ProjectLayoutDetector::boundedContextsOf($files));
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_a_single_module_is_no_split_into_bounded_contexts(): void
    {
        $files = [
            ProjectFile::create('src/Billing/Domain/Invoice.php', '/app/a', '<?php final class Invoice {}'),
            ProjectFile::create('src/Billing/Domain/Payment.php', '/app/b', '<?php final class Payment {}'),
        ];

        self::assertSame([], ProjectLayoutDetector::stylesOf($files));
    }
}
