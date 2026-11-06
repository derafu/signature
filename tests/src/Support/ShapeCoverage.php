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

use Derafu\Signature\Service\SignatureGenerator;
use Derafu\Signature\Service\SignatureService;
use Derafu\Signature\Service\SignatureValidator;
use Derafu\Signature\SignatureValidationResult;
use Derafu\Xml\Service\XmlDecoder;
use Derafu\Xml\Service\XmlEncoder;
use Derafu\Xml\Service\XmlService;
use Derafu\Xml\Service\XmlValidator;
use FilesystemIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use Throwable;

/**
 * Compares the shapes of the signatures of a set of documents with the shapes
 * that the tests of the package exercise (see `SignatureShape`).
 *
 * The shapes that the tests exercise are the ones of the documents of the
 * fixtures and the ones of the documents that the tests sign and validate in
 * the four ways that there are: fixtures validated by the library, signed and
 * validated by the library, signed by `xmlsec1` and validated by the library,
 * and signed by the library and verified by `xmlsec1`. The last three come from
 * the log of the documents (see `SignedDocumentsLog`), that only has the
 * documents whose signatures are all valid.
 */
final class ShapeCoverage
{
    public const FIXTURES = 'fixtures';

    public const LIBRARY_TO_LIBRARY = 'library->library';

    public const XMLSEC_TO_LIBRARY = 'xmlsec->library';

    public const LIBRARY_TO_XMLSEC = 'library->xmlsec';

    /**
     * Ways in which the documents are exercised, that are compared.
     */
    public const MODES = [
        self::FIXTURES,
        self::LIBRARY_TO_LIBRARY,
        self::XMLSEC_TO_LIBRARY,
        self::LIBRARY_TO_XMLSEC,
    ];

    /**
     * Shapes that only some of the ways can exercise, by the design of the
     * library or of `xmlsec1`, with the reason. The key is the start of the
     * atom.
     */
    public const BY_DESIGN = [
        'doc.signatures=0' => 'a document without signatures has nothing to sign or to verify',
        'ref.transforms=dsig:enveloped-signature+' => 'the library writes the enveloped signature transform or the canonicalization, not both',
        'sig.complete=no' => 'a signature without SignedInfo can not be signed, it can only be validated',
        'sig.keyinfo=noKeyValue/x509=0' => 'a signature without certificate can not be signed or validated',
        'sig.method=more:' => 'the library signs with RSA and SHA1',
        'sig.method=-' => 'a signature without SignedInfo can not be signed, it can only be validated',
        'sig.canonicalization=-' => 'a signature without SignedInfo can not be signed, it can only be validated',
        'sig.references=0' => 'a signature without references can not be signed, it can only be validated',
        'sig.references=2' => 'the library signs with only one reference',
        'sig.object=Object' => 'the library does not add objects to the signatures it signs',
        'sig.namespace=custom' => 'xmlsec1 requires the namespace of XML Signature in the signature',
        'ref.transforms=none' => 'the library always writes the transform of the reference',
        'ref.transforms=xpath' => 'the library signs without XPath transforms',
        'ref.transforms=http://' => 'xmlsec1 does not support transforms that are not the ones of XML Signature',
        'ref.digest=enc:' => 'the library signs with SHA1',
        'ref.digest=more:' => 'the library signs with SHA1',
        'ref.identifier=-' => 'there is no signed element to identify',
        'ref.kind=whole' => 'a reference to the whole document has no element that contains signatures or is identified',
        'ref.target=-' => 'there is no signed element',
        'pair prefix+transforms=' => 'the combinations of prefix and transforms depend on the transforms that only some ways support',
        'pair depth+target=' => 'the combinations of depth and target are covered by the atoms that form them',
        'pair encoding+target=' => 'the combinations of encoding and target are covered by the atoms that form them',
        'pair prefix+target=' => 'the combinations of prefix and target are covered by the atoms that form them',
        'pair prefix+depth=' => 'the combinations of prefix and depth are covered by the atoms that form them',
    ];

    /**
     * Expands files and directories to the list of XML files.
     *
     * @param list<string> $paths Files, or directories where the XML files are
     * searched, in all their levels.
     * @return list<string>
     */
    public static function files(array $paths): array
    {
        $files = [];
        foreach ($paths as $path) {
            if (is_dir($path)) {
                $iterator = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS)
                );
                foreach ($iterator as $file) {
                    if ($file instanceof \SplFileInfo && $file->isFile() && strtolower($file->getExtension()) === 'xml') {
                        $files[] = $file->getPathname();
                    }
                }
            } elseif (is_file($path)) {
                $files[] = $path;
            }
        }
        sort($files);

        return array_values(array_unique($files));
    }

    /**
     * Reads a file.
     *
     * @return string|null The content, or `null` if the file can not be read.
     */
    public static function read(string $file): ?string
    {
        if (!is_file($file) || !is_readable($file)) {
            return null;
        }
        $content = file_get_contents($file);

        return $content !== false ? $content : null;
    }

    /**
     * Gives the atoms of the shapes of a set of files, with the number of files
     * that have each one and one file that has it.
     *
     * @param list<string> $files
     * @return array<string, array{count: int, example: string}>
     */
    public static function atomsOf(array $files): array
    {
        $atoms = [];
        foreach ($files as $file) {
            $xml = self::read($file);
            if ($xml === null) {
                continue;
            }
            foreach (SignatureShape::atoms($xml) as $atom) {
                $atoms[$atom] = [
                    'count' => ($atoms[$atom]['count'] ?? 0) + 1,
                    'example' => $atoms[$atom]['example'] ?? $file,
                ];
            }
        }
        ksort($atoms);

        return $atoms;
    }

    /**
     * Gives the atoms that the tests exercise, by the way they do it.
     *
     * @param string $log Path of the log of the documents.
     * @param list<string> $fixtures XML files of the fixtures.
     * @return array<string, array<string, true>> The atoms by way (see
     * `MODES`).
     */
    public static function atomsOfTests(string $log, array $fixtures): array
    {
        $modes = array_fill_keys(self::MODES, []);
        foreach (self::atomsOf($fixtures) as $atom => $info) {
            $modes[self::FIXTURES][$atom] = true;
        }

        $documents = SignedDocumentsLog::read($log);

        // The signatures that each one made, by their value.
        $madeByLibrary = [];
        $madeByXmlsec = [];
        foreach ($documents as $document) {
            if ($document['signature'] === null) {
                continue;
            }
            if ($document['kind'] === SignedDocumentsLog::SIGNED_BY_LIBRARY) {
                $madeByLibrary[$document['signature']] = true;
            } elseif ($document['kind'] === SignedDocumentsLog::SIGNED_BY_XMLSEC) {
                $madeByXmlsec[$document['signature']] = true;
            }
        }

        $service = self::service();
        $seen = [];
        foreach ($documents as $document) {
            if ($document['kind'] === SignedDocumentsLog::VALIDATED_BY_LIBRARY) {
                $key = $document['kind'] . md5($document['xml']);
            } elseif ($document['kind'] === SignedDocumentsLog::VERIFIED_BY_XMLSEC) {
                $key = $document['kind'] . md5($document['xml']) . $document['signature'];
            } else {
                continue;
            }
            if (isset($seen[$key])) {
                continue;
            }
            $seen[$key] = true;

            $values = SignatureShape::signatureValues($document['xml']);
            if ($document['kind'] === SignedDocumentsLog::VALIDATED_BY_LIBRARY) {
                // Only the documents whose signatures are all valid, and in
                // them the signatures that each one made.
                if (!self::isValid($service, $document['xml'])) {
                    continue;
                }
                $ways = [
                    self::LIBRARY_TO_LIBRARY => $madeByLibrary,
                    self::XMLSEC_TO_LIBRARY => $madeByXmlsec,
                ];
            } else {
                // The signature that xmlsec1 verified, if the library made it.
                $verified = $document['signature'] !== null ? [$document['signature'] => true] : [];
                $ways = [self::LIBRARY_TO_XMLSEC => array_intersect_key($madeByLibrary, $verified)];
            }

            foreach ($ways as $mode => $made) {
                $positions = [];
                foreach ($values as $position => $value) {
                    if (isset($made[$value])) {
                        $positions[] = $position;
                    }
                }
                if ($positions === []) {
                    continue;
                }
                foreach (SignatureShape::atoms($document['xml'], $positions) as $atom) {
                    $modes[$mode][$atom] = true;
                }
            }
        }

        return $modes;
    }

    /**
     * Gives the atoms of the documents that the tests do not exercise in the
     * ways that are expected.
     *
     * An atom has to be exercised by the fixtures and, if the design of the
     * library and of `xmlsec1` allows it (see `BY_DESIGN`), in the three other
     * ways.
     *
     * @param array<string, array{count: int, example: string}> $documents
     * @param array<string, array<string, true>> $tests
     * @return array<string, list<string>> The ways that are missing, by atom.
     */
    public static function missing(array $documents, array $tests): array
    {
        $missing = [];
        foreach (array_keys($documents) as $atom) {
            if (self::reason($atom) !== null) {
                $needed = [self::FIXTURES];
            } else {
                $needed = self::MODES;
            }

            $lacking = array_values(array_filter(
                $needed,
                static fn (string $mode): bool => !isset($tests[$mode][$atom])
            ));
            if ($lacking !== []) {
                $missing[$atom] = $lacking;
            }
        }

        return $missing;
    }

    /**
     * Gives the reason why an atom is not exercised in all the ways, if it is
     * by design.
     */
    public static function reason(string $atom): ?string
    {
        foreach (self::BY_DESIGN as $start => $reason) {
            if (str_starts_with($atom, $start)) {
                return $reason;
            }
        }

        return null;
    }

    private static function isValid(SignatureService $service, string $xml): bool
    {
        try {
            $results = $service->validateXml($xml);
        } catch (Throwable) {
            return false;
        }

        return $results !== [] && array_reduce(
            $results,
            static fn (bool $valid, SignatureValidationResult $result): bool => $valid && $result->isValid(),
            true
        );
    }

    private static function service(): SignatureService
    {
        $xmlService = new XmlService(new XmlEncoder(), new XmlDecoder(), new XmlValidator());
        $generator = new SignatureGenerator($xmlService);

        return new SignatureService($generator, new SignatureValidator($generator, $xmlService));
    }
}
