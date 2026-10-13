<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Console;

use Ruvelo\SecurityAdvisories\Ecosystem;
use Ruvelo\SecurityAdvisories\Exceptions\InvalidThreshold;
use Ruvelo\SecurityAdvisories\Finding;
use Ruvelo\SecurityAdvisories\Report;
use Ruvelo\SecurityAdvisories\Threshold;
use Ruvelo\SecurityAlerts\Service\CheckOutcome;
use Ruvelo\SecurityAlerts\Service\Checker;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

#[AsCommand(name: 'ruvelo:security-alerts:check', description: 'Check shopware/core and Composer-installed plugins for known vulnerabilities, exploited ones first')]
class CheckCommand extends Command
{
    public const EXIT_FINDINGS = 1;
    public const EXIT_INCOMPLETE = 2;

    public function __construct(private readonly Checker $checker)
    {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->addOption('json', null, InputOption::VALUE_NONE, 'Print the report as JSON')
            ->addOption('fail-on', null, InputOption::VALUE_REQUIRED, 'Exit with 1 when a finding is at least: exploited, critical, high, medium or any')
            ->addOption('dry-run', null, InputOption::VALUE_NONE, 'Only report: store nothing, send no email, dispatch no event')
            ->addOption('fresh', null, InputOption::VALUE_NONE, 'Ignore cached advisories');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $threshold = null;
        $failOn = $input->getOption('fail-on');
        if (is_string($failOn) && $failOn !== '') {
            try {
                $threshold = Threshold::parse($failOn);
            } catch (InvalidThreshold $e) {
                $output->writeln('<error>'.$e->getMessage().'</error>');

                return self::EXIT_INCOMPLETE;
            }
        }

        $fresh = (bool) $input->getOption('fresh');
        $outcome = $input->getOption('dry-run') ? $this->checker->scan($fresh) : $this->checker->run($fresh);

        if ($input->getOption('json')) {
            $output->writeln((string) json_encode($outcome->toArray(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
        } else {
            $this->render($outcome, $output);
        }

        if ($threshold !== null && $outcome->report->failsOn($threshold)) {
            return self::EXIT_FINDINGS;
        }

        return $outcome->report->isComplete() ? self::SUCCESS : self::EXIT_INCOMPLETE;
    }

    private function render(CheckOutcome $outcome, OutputInterface $output): void
    {
        $report = $outcome->report;

        foreach ($report->problems as $problem) {
            $output->writeln('<comment>Warning: '.$problem.'</comment>');
        }

        if ($report->isClean()) {
            $output->writeln(sprintf('No known vulnerabilities in %d Composer packages.', $report->packageCount(Ecosystem::Composer)));
        }

        foreach ($report->findings as $f) {
            /** @var Finding $f */
            $output->writeln(sprintf(
                '%s %s %s: %s',
                $f->isExploited() ? '<error>EXPLOITED — PATCH NOW</error>' : strtoupper($f->severity->label()),
                $f->package,
                $f->installed,
                $f->title
            ));
            $output->writeln(sprintf('    %s | fixed in %s | %s', $f->cve ?? 'no CVE', $f->fixedIn ?? 'no fixed version listed', $f->link ?? 'no link'));
        }

        if (! $report->isClean()) {
            $output->writeln(sprintf("\n%d findings, %d exploited, in %d Composer packages checked.", count($report->findings), count($report->exploited()), $report->packageCount(Ecosystem::Composer)));
        }

        $notChecked = $outcome->notChecked();
        if ($notChecked !== []) {
            $output->writeln(sprintf("\nNot checked (not installed with Composer): %d plugins", count($notChecked)));
            foreach ($notChecked as $package) {
                $output->writeln(sprintf('    %s %s', $package->name, $package->version));
            }
        }

        foreach ($report->notes as $note) {
            $output->writeln(sprintf('Note: %s%s', $note->package !== null ? $note->package.': ' : '', $note->message));
        }

        $output->writeln(sprintf("\nAdvisory source: %s", self::describeSource($report)));

        if ($outcome->notified > 0) {
            $output->writeln(sprintf("\nSent an email about %d findings.", $outcome->notified));
        }
    }

    private static function describeSource(Report $report): string
    {
        return match ($report->source) {
            'valtry' => 'Valtry (signed answers; package names only)',
            'mixed' => 'Valtry and the public feeds (Packagist, CISA)',
            default => 'the public feeds (Packagist, CISA)',
        };
    }
}
