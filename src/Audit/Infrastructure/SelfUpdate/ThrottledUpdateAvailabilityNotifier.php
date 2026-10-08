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

use Override;
use Psr\Clock\ClockInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\Exception\SelfUpdateFailedException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\Exception\UnsupportedSelfUpdatePlatformException;

/**
 * Resolves the latest released version through the shared self-update machinery,
 * throttling the network call to at most once per `throttleSeconds` by caching
 * the answer. The GitHub call only ever happens when the cache is missing or
 * stale and the store can record the new throttle window; a failed call falls
 * back to the last cached answer (or no notice) and still refreshes that
 * window, so the check is silent when offline and never blocks a run more than
 * once a day.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ThrottledUpdateAvailabilityNotifier implements UpdateAvailabilityNotifierInterface
{
    public const int DEFAULT_THROTTLE_SECONDS = 86_400;

    private const string RELEASE_VERSION_PATTERN = '/^\d+\.\d+\.\d+/';

    private const string NOTICE_TEMPLATE = 'A new version (%s) is available. Run "symfony-security-auditor self-update" to upgrade.';

    public function __construct(
        private SelfUpdaterInterface $selfUpdater,
        private UpdateCheckStoreInterface $updateCheckStore,
        private ClockInterface $clock,
        private int $throttleSeconds = self::DEFAULT_THROTTLE_SECONDS,
    ) {}

    #[Override]
    public function availableUpdateNotice(string $currentVersion): ?string
    {
        if (1 !== preg_match(self::RELEASE_VERSION_PATTERN, $currentVersion)) {
            return null;
        }

        $latestVersion = $this->latestVersion($currentVersion);

        if (!ReleaseTag::isValid($latestVersion) || !version_compare($latestVersion, $currentVersion, '>')) {
            return null;
        }

        return \sprintf(self::NOTICE_TEMPLATE, $latestVersion);
    }

    private function latestVersion(string $currentVersion): string
    {
        $cachedState = $this->updateCheckStore->read();
        if ($cachedState instanceof UpdateCheckState && !$this->isStale($cachedState)) {
            return $cachedState->latestVersion;
        }

        return $this->refreshedLatestVersion($currentVersion, $cachedState);
    }

    /**
     * The throttle window is claimed before the lookup: a store that cannot
     * record it (an unwritable or unresolvable cache directory) would
     * otherwise send every single command to GitHub, so the lookup is skipped
     * and the last known answer stands.
     */
    private function refreshedLatestVersion(string $currentVersion, ?UpdateCheckState $updateCheckState): string
    {
        $knownVersion = $updateCheckState->latestVersion ?? $currentVersion;
        if (!$this->updateCheckStore->write(new UpdateCheckState($this->clock->now(), $knownVersion))) {
            return $knownVersion;
        }

        try {
            $latestVersion = $this->selfUpdater->run($currentVersion, true)->latestVersion;
        } catch (SelfUpdateFailedException|UnsupportedSelfUpdatePlatformException) {
            return $knownVersion;
        }

        $this->updateCheckStore->write(new UpdateCheckState($this->clock->now(), $latestVersion));

        return $latestVersion;
    }

    private function isStale(UpdateCheckState $updateCheckState): bool
    {
        return $this->clock->now()->getTimestamp() - $updateCheckState->checkedAt->getTimestamp() >= $this->throttleSeconds;
    }
}
