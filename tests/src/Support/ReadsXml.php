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
use DOMXPath;

/**
 * Reads the elements of a signed document that a test wants to look at.
 */
trait ReadsXml
{
    /**
     * Gives the first element that an XPath finds in a document.
     *
     * @param array<string, string> $namespaces Prefixes of the XPath and their
     * namespaces.
     */
    private function firstElement(string $xml, string $query, array $namespaces = []): DOMElement
    {
        $doc = new DOMDocument();
        $doc->loadXML($xml);
        $xpath = new DOMXPath($doc);
        foreach ($namespaces as $prefix => $namespace) {
            $xpath->registerNamespace($prefix, $namespace);
        }

        $nodes = $xpath->query($query);
        if ($nodes === false) {
            $this->fail('The XPath ' . $query . ' is not valid.');
        }
        $node = $nodes->item(0);
        if (!$node instanceof DOMElement) {
            $this->fail('The XPath ' . $query . ' does not find an element.');
        }

        return $node;
    }
}
