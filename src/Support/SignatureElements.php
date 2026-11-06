<?php

declare(strict_types=1);

/**
 * Derafu: Signature - Library for digital signatures.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Signature\Support;

use Derafu\Xml\Contract\XmlDocumentInterface;
use DOMElement;
use DOMXPath;

/**
 * Finds the electronic signatures of an XML document.
 */
final class SignatureElements
{
    /**
     * Finds the `Signature` elements of a document, in document order, without
     * the root element.
     *
     * An element is found by its local name, so it does not matter the prefix
     * of its namespace (`Signature`, `ds:Signature`). It is an electronic
     * signature if it is in the namespace of XML Signature or it has a
     * `SignedInfo`, which is the case of the signatures that use another
     * namespace. Other elements named `Signature`, like the `cac:Signature` of
     * UBL, are not.
     *
     * @return list<DOMElement>
     */
    public static function find(XmlDocumentInterface $doc): array
    {
        $nodes = (new DOMXPath($doc->getDomDocument()))->query(
            "/*//*[local-name()='Signature']"
            . "[namespace-uri()='http://www.w3.org/2000/09/xmldsig#' or *[local-name()='SignedInfo']]"
        );

        $elements = [];
        foreach ($nodes !== false ? $nodes : [] as $node) {
            if ($node instanceof DOMElement) {
                $elements[] = $node;
            }
        }

        return $elements;
    }
}
