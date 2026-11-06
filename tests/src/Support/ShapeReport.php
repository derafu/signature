<?php

declare(strict_types=1);

/**
 * Derafu: Signature - Library for digital signatures.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsSignature\Support;

/**
 * Text reports about the shapes of the signatures of a set of documents (see
 * `SignatureShape` and `ShapeCoverage`). They do not have the content of the
 * documents.
 */
final class ShapeReport
{
    /**
     * Report of the shapes of the signatures that a set of files has.
     *
     * @param list<string> $files
     */
    public static function shapes(array $files): string
    {
        $shapes = [];
        $withoutSignatures = 0;
        $unreadable = 0;
        foreach ($files as $file) {
            $xml = ShapeCoverage::read($file);
            if ($xml === null || SignatureShape::atoms($xml) === []) {
                $unreadable++;
                continue;
            }

            $lines = SignatureShape::describe($xml);
            if ($lines === []) {
                $withoutSignatures++;
            }
            foreach ($lines as $line) {
                $shapes[$line] = [
                    'count' => ($shapes[$line]['count'] ?? 0) + 1,
                    'example' => $shapes[$line]['example'] ?? $file,
                ];
            }
        }
        uasort($shapes, static fn (array $a, array $b): int => $b['count'] <=> $a['count']);

        $report = sprintf(
            "Files: %d. Without signatures: %d. Not XML or not readable: %d.\nShapes of signatures: %d.\n",
            count($files),
            $withoutSignatures,
            $unreadable,
            count($shapes)
        );
        foreach ($shapes as $line => $shape) {
            $report .= sprintf("\n%5d  %s\n       e.g. %s\n", $shape['count'], $line, $shape['example']);
        }

        return $report;
    }

    /**
     * Report of the atoms of the shapes of a set of files and how the tests
     * exercise them.
     *
     * @param array<string, array{count: int, example: string}> $documents
     * @param array<string, array<string, true>> $tests
     */
    public static function coverage(array $documents, array $tests): string
    {
        $report = "Characteristics of the signatures of the documents, and the ways in which the tests exercise them\n"
            . "(F fixtures, L signed and validated by the library, X signed by xmlsec1 and validated by the library,\n"
            . "V signed by the library and verified by xmlsec1)\n";

        $group = '';
        foreach ($documents as $atom => $info) {
            [$name, $value] = explode('=', $atom, 2) + [1 => ''];
            if ($name !== $group) {
                $report .= "\n[" . $name . "]\n";
                $group = $name;
            }

            $marks = '';
            foreach (['F' => ShapeCoverage::FIXTURES, 'L' => ShapeCoverage::LIBRARY_TO_LIBRARY, 'X' => ShapeCoverage::XMLSEC_TO_LIBRARY, 'V' => ShapeCoverage::LIBRARY_TO_XMLSEC] as $mark => $mode) {
                $marks .= isset($tests[$mode][$atom]) ? $mark : '.';
            }
            $report .= sprintf("%6d  %s  %s\n", $info['count'], $marks, $value);
        }

        $missing = ShapeCoverage::missing($documents, $tests);
        $report .= "\n" . str_repeat('-', 78) . "\n";
        if ($missing === []) {
            return $report . "All the characteristics are exercised in the ways that are expected.\n";
        }

        $report .= "Characteristics that the tests do not exercise in all the ways that are expected:\n";
        foreach ($missing as $atom => $modes) {
            $report .= sprintf(
                "\n%6d  %s\n        missing: %s\n        e.g. %s\n",
                $documents[$atom]['count'],
                $atom,
                implode(', ', $modes),
                $documents[$atom]['example']
            );
        }

        $report .= "\nCharacteristics that are not exercised in all the ways by design are only expected in the fixtures:\n";
        $reasons = [];
        foreach (array_keys($documents) as $atom) {
            $reason = ShapeCoverage::reason($atom);
            if ($reason !== null) {
                $reasons[$reason] = true;
            }
        }
        foreach (array_keys($reasons) as $reason) {
            $report .= '  - ' . $reason . "\n";
        }

        return $report;
    }
}
