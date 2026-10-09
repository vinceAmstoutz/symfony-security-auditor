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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Command;

use LogicException;
use Override;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\BufferedOutput;
use Symfony\Component\Console\Output\ConsoleOutputInterface;
use Symfony\Component\Console\Output\ConsoleSectionOutput;
use Symfony\Component\Console\Output\Output;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\PricingProviderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Command\UnpricedModelBudgetGuard;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\WarningCollectingLogger;

final class UnpricedModelBudgetGuardTest extends TestCase
{
    public function test_it_notifies_but_permits_the_run_when_a_model_is_unpriced_without_a_cost_budget(): void
    {
        $unpricedModelBudgetGuard = new UnpricedModelBudgetGuard($this->pricingKnowing(), ['unpriced-model']);
        $bufferedOutput = new BufferedOutput();
        $input = $this->nonInteractiveInput();

        self::assertTrue($unpricedModelBudgetGuard->permitsRun($input, new SymfonyStyle($input, $bufferedOutput)));
        $rendered = $bufferedOutput->fetch();
        self::assertStringContainsString('No published pricing', $rendered);
        self::assertStringContainsString('unpriced-model', $rendered);
        self::assertStringNotContainsString('audit.budget.max_cost_usd', $rendered);
    }

    public function test_it_stays_silent_and_permits_the_run_when_every_model_is_priced(): void
    {
        $unpricedModelBudgetGuard = new UnpricedModelBudgetGuard($this->pricingKnowing('claude-opus-4-8'), ['claude-opus-4-8'], 10.0);
        $bufferedOutput = new BufferedOutput();
        $input = $this->nonInteractiveInput();

        self::assertTrue($unpricedModelBudgetGuard->permitsRun($input, new SymfonyStyle($input, $bufferedOutput)));
        self::assertSame('', $bufferedOutput->fetch());
    }

    public function test_it_fails_closed_in_non_interactive_mode_when_a_model_is_unpriced(): void
    {
        $unpricedModelBudgetGuard = new UnpricedModelBudgetGuard($this->pricingKnowing('claude-opus-4-8'), ['claude-opus-4-8', 'mystery-model'], 10.0);
        $bufferedOutput = new BufferedOutput();
        $input = $this->nonInteractiveInput();

        self::assertFalse($unpricedModelBudgetGuard->permitsRun($input, new SymfonyStyle($input, $bufferedOutput)));
        $rendered = $bufferedOutput->fetch();
        self::assertStringContainsString('mystery-model', $rendered);
        self::assertStringContainsString('audit.budget.max_cost_usd', $rendered);
        self::assertStringContainsString('non-interactive', $rendered);
        $unwrapped = (string) preg_replace('/\s+/', ' ', $rendered);
        self::assertStringContainsString('[ERROR] Refusing to start a budgeted audit with an unpriceable model in non-interactive mode. Configure a model with published pricing, or remove audit.budget.max_cost_usd.', $unwrapped);
        self::assertStringNotContainsString('Unpriced model(s)', $unwrapped);
    }

    public function test_it_warns_in_the_log_of_a_budget_it_cannot_enforce_on_unpriced_models_without_asking_anyone(): void
    {
        $unpricedModelBudgetGuard = new UnpricedModelBudgetGuard($this->pricingKnowing('claude-opus-4-8'), ['claude-opus-4-8', 'mystery-model', 'other-model', 'mystery-model'], 10.5);
        $warningCollectingLogger = new WarningCollectingLogger();

        $unpricedModelBudgetGuard->warnWhenBudgetCannotBeEnforced($warningCollectingLogger);

        self::assertSame(
            [[
                'The cost budget audit.budget.max_cost_usd = 10.5 cannot be enforced for the unpriced model(s) mystery-model, other-model: the audit runs, and its real spend may exceed it.',
                ['models' => ['mystery-model', 'other-model'], 'max_cost_usd' => 10.5],
            ]],
            $warningCollectingLogger->warnings,
        );
    }

    public function test_it_does_not_warn_in_the_log_without_a_cost_budget(): void
    {
        $warningCollectingLogger = new WarningCollectingLogger();

        (new UnpricedModelBudgetGuard($this->pricingKnowing(), ['mystery-model']))->warnWhenBudgetCannotBeEnforced($warningCollectingLogger);

        self::assertSame([], $warningCollectingLogger->warnings);
    }

    public function test_it_does_not_warn_in_the_log_when_every_model_is_priced(): void
    {
        $warningCollectingLogger = new WarningCollectingLogger();

        (new UnpricedModelBudgetGuard($this->pricingKnowing('claude-opus-4-8'), ['claude-opus-4-8'], 10.0))->warnWhenBudgetCannotBeEnforced($warningCollectingLogger);

        self::assertSame([], $warningCollectingLogger->warnings);
    }

    public function test_it_permits_the_run_when_the_user_confirms_interactively(): void
    {
        $unpricedModelBudgetGuard = new UnpricedModelBudgetGuard($this->pricingKnowing(), ['mystery-model'], 10.0);
        $bufferedOutput = new BufferedOutput();
        $input = $this->interactiveInput("yes\n");

        self::assertTrue($unpricedModelBudgetGuard->permitsRun($input, new SymfonyStyle($input, $bufferedOutput)));
        self::assertStringContainsString('audit.budget.max_cost_usd', $bufferedOutput->fetch());
    }

    public function test_it_sends_the_interactive_confirmation_prompt_to_stderr_not_stdout(): void
    {
        $unpricedModelBudgetGuard = new UnpricedModelBudgetGuard($this->pricingKnowing(), ['mystery-model'], 10.0);
        $bufferedOutput = new BufferedOutput();
        $consoleOutput = new class($bufferedOutput) extends Output implements ConsoleOutputInterface {
            private string $buffer = '';

            public function __construct(private OutputInterface $errorOutput)
            {
                parent::__construct();
            }

            #[Override]
            protected function doWrite(string $message, bool $newline): void
            {
                $this->buffer .= $message.($newline ? "\n" : '');
            }

            public function fetch(): string
            {
                return $this->buffer;
            }

            #[Override]
            public function getErrorOutput(): OutputInterface
            {
                return $this->errorOutput;
            }

            #[Override]
            public function setErrorOutput(OutputInterface $error): void
            {
                $this->errorOutput = $error;
            }

            #[Override]
            public function section(): ConsoleSectionOutput
            {
                throw new LogicException('Sections are not supported by this test double.');
            }
        };
        $input = $this->interactiveInput("yes\n");

        $unpricedModelBudgetGuard->permitsRun($input, new SymfonyStyle($input, $consoleOutput));

        self::assertStringNotContainsString('Continue anyway', $consoleOutput->fetch());
        self::assertStringContainsString('Continue anyway', $bufferedOutput->fetch());
    }

    public function test_it_aborts_the_run_when_the_user_declines_interactively(): void
    {
        $unpricedModelBudgetGuard = new UnpricedModelBudgetGuard($this->pricingKnowing(), ['mystery-model'], 10.0);
        $bufferedOutput = new BufferedOutput();
        $input = $this->interactiveInput("no\n");

        self::assertFalse($unpricedModelBudgetGuard->permitsRun($input, new SymfonyStyle($input, $bufferedOutput)));
    }

    public function test_it_defaults_to_aborting_when_the_user_just_presses_enter(): void
    {
        $unpricedModelBudgetGuard = new UnpricedModelBudgetGuard($this->pricingKnowing(), ['mystery-model'], 10.0);
        $bufferedOutput = new BufferedOutput();
        $input = $this->interactiveInput("\n");

        self::assertFalse($unpricedModelBudgetGuard->permitsRun($input, new SymfonyStyle($input, $bufferedOutput)));
    }

    private function pricingKnowing(string ...$pricedModels): PricingProviderInterface
    {
        $pricing = self::createStub(PricingProviderInterface::class);
        $pricing->method('hasModel')->willReturnCallback(
            static fn (string $model): bool => \in_array($model, $pricedModels, true),
        );

        return $pricing;
    }

    private function nonInteractiveInput(): InputInterface
    {
        $arrayInput = new ArrayInput([]);
        $arrayInput->setInteractive(false);

        return $arrayInput;
    }

    private function interactiveInput(string $answer): InputInterface
    {
        $arrayInput = new ArrayInput([]);
        $arrayInput->setInteractive(true);

        $stream = fopen('php://memory', 'r+');
        self::assertIsResource($stream);
        fwrite($stream, $answer);
        rewind($stream);
        $arrayInput->setStream($stream);

        return $arrayInput;
    }
}
