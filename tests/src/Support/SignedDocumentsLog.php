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
 * Log of the documents that the tests sign, validate and verify, to know which
 * shapes of signatures the tests exercise (see `SignatureShape`).
 *
 * The log is only written if the environment variable
 * `DERAFU_SIGNATURE_SHAPES_LOG` has the path of the file where to write it.
 */
final class SignedDocumentsLog
{
    public const ENVIRONMENT_VARIABLE = 'DERAFU_SIGNATURE_SHAPES_LOG';

    /**
     * Document that the library signed.
     */
    public const SIGNED_BY_LIBRARY = 'signed-by-library';

    /**
     * Document that `xmlsec1` signed.
     */
    public const SIGNED_BY_XMLSEC = 'signed-by-xmlsec';

    /**
     * Document that the library validated.
     */
    public const VALIDATED_BY_LIBRARY = 'validated-by-library';

    /**
     * Document that `xmlsec1` verified.
     */
    public const VERIFIED_BY_XMLSEC = 'verified-by-xmlsec';

    /**
     * Adds a document to the log, if the log is enabled.
     *
     * @param string $kind What happened to the document, one of the constants.
     * @param string|null $signature Value of the signature (see
     * `SignatureShape::signatureValues()`) that was made or verified, if it is
     * one signature of the document.
     */
    public static function record(string $kind, string $xml, ?string $signature = null): void
    {
        $file = getenv(self::ENVIRONMENT_VARIABLE);
        if (!is_string($file) || $file === '') {
            return;
        }

        file_put_contents($file, $kind . ' ' . ($signature !== null && $signature !== '' ? $signature : '-') . ' ' . base64_encode($xml) . "\n", FILE_APPEND | LOCK_EX);
    }

    /**
     * Reads a log.
     *
     * @return list<array{kind: string, signature: string|null, xml: string}> The documents,
     * in the order they were recorded.
     */
    public static function read(string $file): array
    {
        $documents = [];
        foreach (file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $line) {
            [$kind, $signature, $encoded] = explode(' ', $line, 3) + [1 => '-', 2 => ''];
            $xml = base64_decode($encoded, true);
            if ($xml !== false) {
                $documents[] = ['kind' => $kind, 'signature' => $signature !== '-' ? $signature : null, 'xml' => $xml];
            }
        }

        return $documents;
    }
}
