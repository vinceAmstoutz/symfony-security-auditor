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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate;

use Closure;
use Override;
use Symfony\Component\Process\Exception\ExceptionInterface;
use Symfony\Component\Process\Process;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\Exception\SelfUpdateFailedException;

/**
 * Fetches release metadata and assets with `curl` through Symfony `Process` —
 * the same subprocess-only convention `ComposerBridgeInstaller` uses — so the
 * binary needs no bundled HTTP client.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ProcessReleaseClient implements ReleaseClientInterface
{
    private const string USER_AGENT = 'symfony-security-auditor-self-update';

    private const int CONNECT_TIMEOUT_SECONDS = 30;

    private const int MAX_TRANSFER_SECONDS = 600;

    private const float PROCESS_TIMEOUT_SECONDS = 660.0;

    /**
     * @param Closure(list<string>): Process $processBuilder the curl command builder (use self::defaultProcessBuilder() in production); tests inject a stub
     */
    public function __construct(
        private Closure $processBuilder,
    ) {}

    /**
     * @return Closure(list<string>): Process
     */
    public static function defaultProcessBuilder(): Closure
    {
        return
            /** @param list<string> $arguments */
            static function (array $arguments): Process {
                /** @var list<string> $command */
                $command = [
                    'curl',
                    '-fsSL',
                    '--connect-timeout',
                    (string) self::CONNECT_TIMEOUT_SECONDS,
                    '--max-time',
                    (string) self::MAX_TRANSFER_SECONDS,
                    '-H',
                    \sprintf('User-Agent: %s', self::USER_AGENT),
                    ...$arguments,
                ];
                $process = new Process($command);
                $process->setTimeout(self::PROCESS_TIMEOUT_SECONDS);

                return $process;
            };
    }

    /**
     * @throws SelfUpdateFailedException
     */
    #[Override]
    public function get(string $url): string
    {
        return $this->run([$url], $url)->getOutput();
    }

    /**
     * @throws SelfUpdateFailedException
     */
    #[Override]
    public function download(string $url, string $destination): void
    {
        $this->run(['--output', $destination, $url], $url);
    }

    /**
     * @param list<string> $arguments
     *
     * @throws SelfUpdateFailedException
     */
    private function run(array $arguments, string $url): Process
    {
        $process = ($this->processBuilder)($arguments);

        try {
            $process->run();
        } catch (ExceptionInterface $exception) {
            throw SelfUpdateFailedException::forFailedDownload($url, $exception);
        }

        if (!$process->isSuccessful()) {
            throw SelfUpdateFailedException::forFailedDownload($url);
        }

        return $process;
    }
}
