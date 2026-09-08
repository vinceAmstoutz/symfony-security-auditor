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
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Model\FormBinding;

final class FormBindingTest extends TestCase
{
    public function test_it_exposes_controller_action_and_form_type(): void
    {
        $formBinding = new FormBinding(
            entrypointFilePath: 'src/Controller/UserController.php',
            controllerMethod: 'edit',
            formTypeClass: 'App\\Form\\UserType',
        );

        self::assertSame('src/Controller/UserController.php', $formBinding->entrypointFilePath());
        self::assertSame('edit', $formBinding->controllerMethod());
        self::assertSame('App\\Form\\UserType', $formBinding->formTypeClass());
    }
}
