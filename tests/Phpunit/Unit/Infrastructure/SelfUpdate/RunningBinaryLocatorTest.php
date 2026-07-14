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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\SelfUpdate;

use Override;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\Exception\SelfUpdateFailedException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\RunningBinaryLocator;

final class RunningBinaryLocatorTest extends TestCase
{
    private string $workingDirectory;

    #[Override]
    protected function setUp(): void
    {
        $this->workingDirectory = sys_get_temp_dir().'/ssa-locator-'.bin2hex(random_bytes(6));
        (new Filesystem())->mkdir($this->workingDirectory);
    }

    #[Override]
    protected function tearDown(): void
    {
        (new Filesystem())->remove($this->workingDirectory);
    }

    /**
     * @throws SelfUpdateFailedException
     */
    public function test_it_returns_the_kernel_reported_executable_when_proc_self_exe_is_a_link(): void
    {
        $target = $this->workingDirectory.'/actual-binary';
        (new Filesystem())->touch($target);
        $procSelfExe = $this->workingDirectory.'/proc-self-exe';
        symlink($target, $procSelfExe);

        self::assertSame($target, (new RunningBinaryLocator($procSelfExe, ''))->path());
    }

    /**
     * @throws SelfUpdateFailedException
     */
    public function test_it_prefers_the_kernel_reported_executable_over_the_invoked_script(): void
    {
        $kernelTarget = $this->workingDirectory.'/kernel-binary';
        (new Filesystem())->touch($kernelTarget);
        $procSelfExe = $this->workingDirectory.'/proc-self-exe';
        symlink($kernelTarget, $procSelfExe);
        $invokedScript = $this->workingDirectory.'/invoked-binary';
        (new Filesystem())->touch($invokedScript);

        self::assertSame($kernelTarget, (new RunningBinaryLocator($procSelfExe, $invokedScript))->path());
    }

    /**
     * @throws SelfUpdateFailedException
     */
    public function test_it_falls_back_to_the_resolved_invoked_script_when_proc_self_exe_is_absent(): void
    {
        $invokedScript = $this->workingDirectory.'/invoked-binary';
        (new Filesystem())->touch($invokedScript);

        self::assertSame($invokedScript, (new RunningBinaryLocator($this->workingDirectory.'/missing', $invokedScript))->path());
    }

    /**
     * @throws SelfUpdateFailedException
     */
    #[DataProvider('unresolvableInvokedScriptCases')]
    public function test_it_fails_when_neither_source_resolves_a_path(string $invokedScriptPath): void
    {
        $this->expectException(SelfUpdateFailedException::class);

        (new RunningBinaryLocator($this->workingDirectory.'/missing', $invokedScriptPath))->path();
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function unresolvableInvokedScriptCases(): iterable
    {
        yield 'no invoked script provided' => [''];
        yield 'invoked script does not exist' => [sys_get_temp_dir().'/ssa-locator-also-missing'];
    }
}
