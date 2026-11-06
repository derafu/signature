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
use DOMNode;
use DOMXPath;

/**
 * Finds the element that a `Reference` of an XML signature points to.
 */
final class ReferenceTarget
{
    /**
     * Attributes that identify an element, in the order they are searched:
     * `ID` is the one of the SII, `Id` the one of XML Signature and XAdES, and
     * `xml:id` and `id` the ones of other documents.
     */
    private const array ATTRIBUTES = ['@ID', '@Id', '@xml:id', '@id'];

    /**
     * Finds the element with an identifier.
     *
     * @param XmlDocumentInterface $doc Document where the element is.
     * @param string $reference Identifier, with or without the `#` prefix.
     * @return DOMNode|null The element, or `null` if there is none.
     */
    public static function find(XmlDocumentInterface $doc, string $reference): ?DOMNode
    {
        $id = DOMXPath::quote(ltrim($reference, '#'));
        $xpath = new DOMXPath($doc->getDomDocument());

        foreach (self::ATTRIBUTES as $attribute) {
            $nodes = $xpath->query('//*[' . $attribute . '=' . $id . ']');
            $node = $nodes !== false ? $nodes->item(0) : null;
            if ($node instanceof DOMNode) {
                return $node;
            }
        }

        return null;
    }
}
