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
 * binary needs no bundled HTTP client. Metadata lookups (`get()`) run behind
 * the after-command update notice, so they are bounded tightly — 20 seconds and
 * 1 MiB, ample for release JSON and a checksum line; only downloads
 * (`download()`) keep a transfer window of 10 minutes and a 256 MiB body cap,
 * sized for a large binary on a slow link. Every request is pinned to HTTPS
 * with TLS 1.2 or newer, redirects included, so a redirect cannot leave HTTPS.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ProcessReleaseClient implements ReleaseClientInterface
{
    private const string USER_AGENT = 'symfony-security-auditor-self-update';

    private const string CONNECT_TIMEOUT_SECONDS = '10';

    private const string METADATA_MAX_TRANSFER_SECONDS = '20';

    private const string DOWNLOAD_MAX_TRANSFER_SECONDS = '600';

    private const string METADATA_MAX_FILESIZE_BYTES = '1048576';

    private const string DOWNLOAD_MAX_FILESIZE_BYTES = '268435456';

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
                    '--proto',
                    '=https',
                    '--tlsv1.2',
                    '--connect-timeout',
                    self::CONNECT_TIMEOUT_SECONDS,
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
        return $this->run(['--max-time', self::METADATA_MAX_TRANSFER_SECONDS, '--max-filesize', self::METADATA_MAX_FILESIZE_BYTES, $url], $url)->getOutput();
    }

    /**
     * @throws SelfUpdateFailedException
     */
    #[Override]
    public function download(string $url, string $destination): void
    {
        $this->run(['--max-time', self::DOWNLOAD_MAX_TRANSFER_SECONDS, '--output', $destination, '--max-filesize', self::DOWNLOAD_MAX_FILESIZE_BYTES, $url], $url);
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
