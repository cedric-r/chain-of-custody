<?php
// tests/run_coverage.php
// Collects line coverage across all test files and reports uncovered lines.
// Run as: php -d xdebug.mode=coverage tests/run_coverage.php
//
// Each test file is run as a sub-process with a shutdown function that dumps
// coverage data before the test file's exit() call terminates the process.

if (!extension_loaded('xdebug')) {
    echo "Xdebug not available. Run individual test files instead.\n";
    exit(1);
}

$srcDir   = realpath(__DIR__ . '/../src');
$testDir  = __DIR__;

// Determine the test files
$testFiles = [];
foreach (glob($testDir . '/*.php') as $file) {
    $base = basename($file);
    if (in_array($base, ['run_coverage.php', 'config.php', 'config.example.php', '_salted_config.php'], true)) {
        continue;
    }
    $testFiles[] = $file;
}
sort($testFiles);

$combinedCoverage = [];

foreach ($testFiles as $file) {
    $tmpFile = tempnam(sys_get_temp_dir(), 'cov_');

    // Wrapper: register shutdown to save coverage, then include the test file.
    // The shutdown function runs even when the included file calls exit().
    $wrapper = '<?php
        $covFile = ' . var_export($tmpFile, true) . ';
        register_shutdown_function(function () use ($covFile) {
            $data = @xdebug_get_code_coverage();
            if (is_array($data)) {
                @file_put_contents($covFile, serialize($data));
            }
        });
        xdebug_start_code_coverage(' . (XDEBUG_CC_UNUSED | XDEBUG_CC_DEAD_CODE) . ');
        include ' . var_export($file, true) . ';
    ';

    $wrapperPath = tempnam(sys_get_temp_dir(), 'wrap_');
    file_put_contents($wrapperPath, $wrapper);

    $output = [];
    $code = 0;
    exec(
        'php -d xdebug.mode=coverage ' . escapeshellarg($wrapperPath) . ' 2>&1',
        $output,
        $code
    );

    echo implode("\n", $output) . "\n";

    // Read coverage data saved by shutdown function
    if (file_exists($tmpFile)) {
        $raw = file_get_contents($tmpFile);
        if ($raw !== false) {
            $data = @unserialize($raw);
            if (is_array($data)) {
                foreach ($data as $filePath => $lines) {
                    if (!isset($combinedCoverage[$filePath])) {
                        $combinedCoverage[$filePath] = $lines;
                    } else {
                        foreach ($lines as $line => $count) {
                            if (!isset($combinedCoverage[$filePath][$line]) || $count > $combinedCoverage[$filePath][$line]) {
                                $combinedCoverage[$filePath][$line] = $count;
                            }
                        }
                    }
                }
            }
        }
        @unlink($tmpFile);
    }

    @unlink($wrapperPath);
}

// ===========================================================================
// Coverage Report
// ===========================================================================

$report = [];
foreach ($combinedCoverage as $file => $lines) {
    $real = realpath($file);
    if ($real === false) continue;
    if (strpos($real, $srcDir) !== 0) continue;

    $missed = [];
    foreach ($lines as $line => $count) {
        if ($count === -1) $missed[] = $line;
    }
    if ($missed) {
        $report[$real] = $missed;
    }
}

if (empty($report)) {
    echo "\n[COVERAGE] All executable lines in src/ were hit.\n";
} else {
    echo "\n[COVERAGE] Uncovered lines:\n";
    foreach ($report as $file => $lines) {
        $short = str_replace($srcDir . '/', 'src/', $file);
        echo "  {$short}: lines " . implode(', ', $lines) . "\n";
    }
    echo "\n";
}
