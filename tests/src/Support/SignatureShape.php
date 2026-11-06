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

use DOMDocument;
use DOMElement;
use DOMNameSpaceNode;
use DOMNode;
use DOMXPath;

/**
 * Describes the shape of the electronic signatures of an XML document: how the
 * signature is written and what it covers, without the content of the document.
 *
 * The shape has no data of the document (no identifiers, texts, values or
 * names), only its structure: the prefix of the signature, if it is nested,
 * the algorithms, the transforms, the attribute that identifies the signed
 * element, if the signed element has other signatures inside, the encoding and
 * the format of the document. It can be shown or shared without showing what
 * the document says.
 *
 * It is used to know which shapes of signatures a set of real documents has
 * and which of them the tests of the package exercise.
 */
final class SignatureShape
{
    private const DSIG = 'http://www.w3.org/2000/09/xmldsig#';

    /**
     * Prefixes of the URIs of the algorithms that are written shorter.
     */
    private const SHORT_URIS = [
        'http://www.w3.org/2000/09/xmldsig#' => 'dsig:',
        'http://www.w3.org/2001/04/xmldsig-more#' => 'more:',
        'http://www.w3.org/2001/04/xmlenc#' => 'enc:',
        'http://www.w3.org/2001/10/xml-exc-c14n#' => 'exc-c14n',
        'http://www.w3.org/TR/2001/REC-xml-c14n-20010315' => 'c14n',
        'http://www.w3.org/TR/1999/REC-xpath-19991116' => 'xpath',
    ];

    /**
     * Query of the elements that are electronic signatures.
     */
    private const SIGNATURES = "*[local-name()='Signature'][namespace-uri()='" . self::DSIG . "' or *[local-name()='SignedInfo']]";

    /**
     * Gives a line for each signature of the document, with its shape. Two
     * signatures with the same line have the same shape.
     *
     * @return list<string> Empty if the document can not be read or has no
     * signatures.
     */
    public static function describe(string $xml): array
    {
        return self::analyze($xml)['lines'] ?? [];
    }

    /**
     * Gives the atoms of the shape of the document: each one of its
     * characteristics, as `name=value`, and some of them that matter together.
     *
     * @param list<int>|null $only Positions of the signatures of the document
     * (the first is 0) whose characteristics are included, the ones of the
     * document are always included. If it is `null`, all the signatures are
     * included.
     * @return list<string> Without repeated atoms. Empty if the document can
     * not be read.
     */
    public static function atoms(string $xml, ?array $only = null): array
    {
        return self::analyze($xml, $only)['atoms'] ?? [];
    }

    /**
     * Gives the value of each signature of the document (its `SignatureValue`,
     * without whitespace), that identifies the signature.
     *
     * @return list<string> One value for each signature of the document, in
     * the order of the document. Empty if the document can not be read.
     */
    public static function signatureValues(string $xml): array
    {
        return self::analyze($xml)['values'] ?? [];
    }

    /**
     * @param list<int>|null $only
     * @return array{lines: list<string>, atoms: list<string>, values: list<string>}|null
     */
    private static function analyze(string $xml, ?array $only = null): ?array
    {
        if (trim($xml) === '') {
            return null;
        }

        $doc = new DOMDocument();
        $doc->preserveWhiteSpace = true;
        $previous = libxml_use_internal_errors(true);
        $loaded = $doc->loadXML($xml);
        libxml_clear_errors();
        libxml_use_internal_errors($previous);
        $root = $doc->documentElement;
        if (!$loaded || $root === null) {
            return null;
        }

        $xpath = new DOMXPath($doc);
        $signatures = self::elements($xpath, '/*//' . self::SIGNATURES);

        $encoding = preg_match('/^<\?xml[^>]*encoding="([^"]+)"/i', $xml, $matches) === 1
            ? strtoupper($matches[1])
            : 'none'
        ;
        $format = preg_match('/>\s*\n\s*</', $xml) === 1 ? 'pretty' : 'compact';
        $extra = 0;
        $namespaces = $xpath->query('namespace::*', $root);
        foreach ($namespaces !== false ? $namespaces : [] as $namespace) {
            if ($namespace instanceof DOMNameSpaceNode && $namespace->prefix !== 'xml') {
                $extra++;
            }
        }

        $atoms = [
            'doc.encoding=' . $encoding,
            'doc.format=' . $format,
            'doc.rootNamespace=' . ($root->namespaceURI !== null ? 'namespaced' : 'none'),
            'doc.namespaceDeclarations=' . min($extra, 3) . ($extra >= 3 ? '+' : ''),
            'doc.signatures=' . min(count($signatures), 3) . (count($signatures) >= 3 ? '+' : ''),
        ];
        $lines = [];
        $values = [];

        foreach ($signatures as $index => $signature) {
            $value = self::elements($xpath, "*[local-name()='SignatureValue']", $signature)[0] ?? null;
            $values[] = $value !== null ? (string) preg_replace('/\s+/', '', $value->textContent) : '';
            if ($only !== null && !in_array($index, $only, true)) {
                continue;
            }

            $depth = 0;
            for ($node = $signature->parentNode; $node !== null && !$node instanceof DOMDocument; $node = $node->parentNode) {
                $depth++;
            }
            $depth = $depth <= 1 ? 'child-of-root' : 'nested';
            $prefix = $signature->prefix === ''
                ? 'none'
                : ($signature->prefix === 'ds' ? 'ds' : 'other')
            ;
            $namespace = $signature->namespaceURI === self::DSIG ? 'dsig' : 'custom';

            $signedInfo = self::elements($xpath, "*[local-name()='SignedInfo']", $signature)[0] ?? null;
            $canonicalization = self::attribute($xpath, "*[local-name()='CanonicalizationMethod']", 'Algorithm', $signedInfo);
            $method = self::attribute($xpath, "*[local-name()='SignatureMethod']", 'Algorithm', $signedInfo);
            $certificates = min(count(self::elements($xpath, ".//*[local-name()='X509Certificate']", $signature)), 2);
            $keyValue = self::elements($xpath, ".//*[local-name()='KeyValue']", $signature) !== [] ? 'KeyValue' : 'noKeyValue';
            $object = self::elements($xpath, "*[local-name()='Object']", $signature) !== [] ? 'Object' : 'none';
            $references = $signedInfo !== null
                ? self::elements($xpath, "*[local-name()='Reference']", $signedInfo)
                : []
            ;

            $complete = $signedInfo !== null ? 'yes' : 'no (no SignedInfo)';
            $atoms[] = 'sig.complete=' . $complete;
            $atoms[] = 'sig.prefix=' . $prefix;
            $atoms[] = 'sig.namespace=' . $namespace;
            $atoms[] = 'sig.depth=' . $depth;
            $atoms[] = 'sig.canonicalization=' . $canonicalization;
            $atoms[] = 'sig.method=' . $method;
            $atoms[] = 'sig.keyinfo=' . $keyValue . '/x509=' . $certificates;
            $atoms[] = 'sig.object=' . $object;
            $atoms[] = 'sig.references=' . count($references);
            $atoms[] = 'pair prefix+depth=' . $prefix . '+' . $depth;

            $shapes = [];
            foreach ($references as $reference) {
                $uri = $reference->getAttribute('URI');
                $kind = $uri === '' ? 'whole' : '#id';
                $transforms = [];
                foreach (self::elements($xpath, "*[local-name()='Transforms']/*[local-name()='Transform']", $reference) as $transform) {
                    $transforms[] = self::short($transform->getAttribute('Algorithm'));
                }
                $transforms = $transforms !== [] ? implode('+', $transforms) : 'none';
                $digest = self::attribute($xpath, "*[local-name()='DigestMethod']", 'Algorithm', $reference);
                [$identifier, $target] = $uri === '' ? ['-', '-'] : self::target($xpath, $uri, $signature);

                $atoms[] = 'ref.kind=' . $kind;
                $atoms[] = 'ref.digest=' . $digest;
                $atoms[] = 'ref.transforms=' . $transforms;
                $atoms[] = 'ref.identifier=' . $identifier;
                $atoms[] = 'ref.target=' . $target;
                $atoms[] = 'pair prefix+transforms=' . $prefix . '+' . $transforms;
                $atoms[] = 'pair depth+target=' . $depth . '+' . $target;
                $atoms[] = 'pair encoding+target=' . $encoding . '+' . $target;
                $atoms[] = 'pair prefix+target=' . $prefix . '+' . $target;
                $shapes[] = implode('|', [$kind, $transforms, $digest, $identifier, $target]);
            }

            $lines[] = implode(' ; ', [
                'prefix=' . $prefix,
                'namespace=' . $namespace,
                'depth=' . $depth,
                'canonicalization=' . $canonicalization,
                'method=' . $method,
                'x509=' . $certificates,
                $keyValue,
                $object,
                'references=[' . implode(' / ', $shapes) . ']',
            ]);
        }

        return ['lines' => $lines, 'atoms' => array_values(array_unique($atoms)), 'values' => $values];
    }

    /**
     * Describes the element that a reference points to: the attribute that
     * identifies it and if it has other signatures inside.
     *
     * @return array{string, string} The attribute (`ID`, `Id`, `id`, or `-`
     * if there is no element) and the description of the element.
     */
    private static function target(DOMXPath $xpath, string $uri, DOMElement $signature): array
    {
        $id = DOMXPath::quote(ltrim($uri, '#'));
        foreach (['ID', 'Id', 'id'] as $attribute) {
            $element = self::elements($xpath, '//*[@' . $attribute . '=' . $id . ']')[0] ?? null;
            if ($element === null) {
                continue;
            }

            $inside = self::elements($xpath, './/' . self::SIGNATURES, $element) !== [] ? 'contains-signature' : 'plain';
            $position = $element->contains($signature) ? 'signature-inside' : 'signature-outside';

            return [$attribute, $inside . '/' . $position];
        }

        return ['-', '-'];
    }

    /**
     * Gives the value of an attribute of the first element that the query
     * finds, with the URIs of the algorithms shortened.
     */
    private static function attribute(DOMXPath $xpath, string $query, string $name, ?DOMNode $context): string
    {
        if ($context === null) {
            return '-';
        }
        $element = self::elements($xpath, $query, $context)[0] ?? null;

        return $element !== null ? self::short($element->getAttribute($name)) : '-';
    }

    /**
     * Writes a URI of an algorithm shorter if it is one of the known ones.
     */
    private static function short(string $uri): string
    {
        foreach (self::SHORT_URIS as $prefix => $short) {
            if (str_starts_with($uri, $prefix)) {
                return $short . substr($uri, strlen($prefix));
            }
        }

        return $uri;
    }

    /**
     * Gives the elements that a query finds.
     *
     * @return list<DOMElement>
     */
    private static function elements(DOMXPath $xpath, string $query, ?DOMNode $context = null): array
    {
        $nodes = $context !== null ? $xpath->query($query, $context) : $xpath->query($query);

        $elements = [];
        foreach ($nodes !== false ? $nodes : [] as $node) {
            if ($node instanceof DOMElement) {
                $elements[] = $node;
            }
        }

        return $elements;
    }
}
