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

use Derafu\Signature\Exception\SignatureException;
use Derafu\Xml\Exception\XmlException;
use Derafu\Xml\XmlDocument;
use Derafu\Xml\XmlHelper;
use DOMDocument;
use DOMElement;
use DOMNameSpaceNode;
use DOMNode;
use DOMXPath;

/**
 * Gives the data of a reference that is digested: the node or the set of nodes
 * that its `URI` points to, after the transforms of the reference, in
 * canonical form.
 *
 * The generator and the validator use it, so a signature is made with the same
 * data that it is validated with.
 */
final class ReferenceData
{
    /**
     * Indicates if the `URI` of a reference points to a resource that is not
     * in the document: it is not empty and it is not a reference to an `Id`.
     */
    public static function isExternal(?string $uri): bool
    {
        return $uri !== null && $uri !== '' && $uri[0] !== '#';
    }

    /**
     * Indicates if a reference of a signature that is validated points to a
     * resource that is not in the document.
     *
     * Some signing systems write the `URI` of an element without the `#`, so
     * a `URI` that does not start with it is a resource that is not in the
     * document only if there is no element with that `Id` there.
     */
    public static function isExternalTo(XmlDocument $doc, ?string $uri): bool
    {
        return self::isExternal($uri) && ReferenceTarget::find($doc, (string) $uri) === null;
    }

    /**
     * Gives the algorithms of the transforms of a reference, in order.
     *
     * @return list<string>
     */
    public static function algorithms(DOMElement $reference): array
    {
        $algorithms = [];
        $transforms = self::childrenByName($reference, 'Transforms')[0] ?? null;
        foreach ($transforms !== null ? self::childrenByName($transforms, 'Transform') : [] as $transform) {
            $algorithms[] = $transform->getAttribute('Algorithm');
        }

        return $algorithms;
    }

    /**
     * Gives the element that a `URI` points to in a document.
     *
     * @param string|null $uri `URI` of the reference. If it is `null` or empty
     * it points to the whole document.
     * @return DOMNode|null The element, or `null` for the whole document.
     * @throws XmlException If the element does not exist.
     */
    public static function target(XmlDocument $doc, ?string $uri): ?DOMNode
    {
        if ($uri === null || $uri === '') {
            return null;
        }

        $target = ReferenceTarget::find($doc, $uri);
        if (!$target instanceof DOMNode) {
            throw new XmlException([
                'No element with ID "{id}" was found in the XML document.',
                'id' => ltrim($uri, '#'),
            ]);
        }

        return $target;
    }

    /**
     * Gives the data of a reference to the document.
     *
     * With an XPath transform the data is a set of nodes of the document (see
     * `canonicalizeNodeSet()`). Without it, it is the element that the `URI`
     * points to, or the whole document, without the signature if the reference
     * has the enveloped signature transform (the whole document is always
     * without it).
     *
     * @param XmlDocument $doc Document where the signature is.
     * @param DOMElement|null $signature Element of the signature in the
     * document.
     * @param DOMElement|null $reference Element `Reference` in the signature.
     * @param string|null $uri `URI` of the reference.
     * @param list<string> $algorithms Algorithms of the transforms.
     * @return string The data in canonical form.
     * @throws SignatureException If the transforms need the signature element
     * and it is not in the document.
     * @throws XmlException If the element of the reference does not exist.
     */
    public static function canonicalize(
        XmlDocument $doc,
        ?DOMElement $signature,
        ?DOMElement $reference,
        ?string $uri,
        array $algorithms
    ): string {
        [$exclusive, $withComments] = self::flags($algorithms);
        $target = self::target($doc, $uri);

        // With an XPath transform the data is a set of nodes of the document.
        if (in_array(Algorithms::XPATH, $algorithms, true)) {
            return self::canonicalizeNodeSet(
                $doc,
                $signature,
                $reference,
                $target,
                $algorithms,
                $exclusive,
                $withComments
            );
        }

        // The whole document, without the signature.
        if ($target === null) {
            $copy = self::copyWithoutSignature($doc, $signature);

            return XmlHelper::canonicalize($copy, $exclusive, $withComments);
        }

        // An element that has the signature inside, with the enveloped
        // signature transform: the signature is not part of the data.
        if ($signature !== null
            && in_array(Algorithms::ENVELOPED, $algorithms, true)
            && self::contains($target, $signature)
        ) {
            $copy = self::copyWithoutSignature($doc, $signature);
            $element = self::find($copy, self::positionalPath($target));
            if ($element !== null) {
                return XmlHelper::canonicalize($element, $exclusive, $withComments);
            }
        }

        return XmlHelper::canonicalize($target, $exclusive, $withComments);
    }

    /**
     * Gives the data of a reference to a resource that is not in the document.
     *
     * If the reference has no transforms the data are the octets of the
     * resource. If it has them, the resource is an XML document, and the
     * transforms are applied to its nodes: the XPath transform filters them and
     * the canonicalization writes them. The `here()` function of the
     * expression has no element in that document, so it is not valid.
     *
     * @param string $content Content of the resource.
     * @param DOMElement|null $reference Element `Reference` in the signature.
     * @param list<string> $algorithms Algorithms of the transforms.
     * @throws SignatureException If the transforms are not valid for the
     * resource.
     */
    public static function canonicalizeExternal(
        string $content,
        ?DOMElement $reference,
        array $algorithms
    ): string {
        if ($algorithms === []) {
            return $content;
        }

        $doc = new XmlDocument();
        $doc->loadXml($content);
        [$exclusive, $withComments] = self::flags($algorithms);

        if (in_array(Algorithms::XPATH, $algorithms, true)) {
            return self::canonicalizeNodeSet(
                $doc,
                null,
                $reference,
                null,
                $algorithms,
                $exclusive,
                $withComments,
                false
            );
        }

        return $doc->C14N($exclusive, $withComments);
    }

    /**
     * Canonicalizes the set of nodes that a reference selects with its
     * transforms, when it has an XPath transform.
     *
     * The set starts with the nodes of the element of the reference, or all the
     * nodes of the document, and each transform filters it: the enveloped
     * signature transform leaves out the signature, and the XPath transform
     * leaves the nodes for which its expression is true. The `here()` function
     * of the expression is the `XPath` element that contains it.
     *
     * @param DOMElement|null $signature Element of the signature in the
     * document.
     * @param DOMElement|null $reference Element `Reference` in the signature.
     * @param DOMNode|null $target Element of the reference, or `null` for the
     * whole document.
     * @param list<string> $algorithms Algorithms of the transforms.
     * @param bool $here Whether the `XPath` element is in the document, so the
     * expression can use `here()`.
     * @throws SignatureException If the element of the signature is not in the
     * document, or the reference does not have the transforms it declares, or
     * the expression uses `here()` and it can not.
     */
    private static function canonicalizeNodeSet(
        XmlDocument $doc,
        ?DOMElement $signature,
        ?DOMElement $reference,
        ?DOMNode $target,
        array $algorithms,
        bool $exclusive,
        bool $withComments,
        bool $here = true
    ): string {
        $transforms = $reference !== null ? (self::childrenByName($reference, 'Transforms')[0] ?? null) : null;
        if ($transforms === null || ($here && $signature === null)) {
            throw new SignatureException(
                'The signature element with the transforms of the reference was not found in the XML to validate.'
            );
        }

        if ($target === null) {
            $nodes = '(//. | //@* | //namespace::*)';
        } else {
            $path = self::positionalPath($target);
            $nodes = '(' . $path . '/descendant-or-self::node() | '
                . $path . '/descendant-or-self::*/@* | '
                . $path . '/descendant-or-self::*/namespace::*)';
        }

        $query = $nodes;
        $namespaces = [];
        foreach (self::childrenByName($transforms, 'Transform') as $transform) {
            $algorithm = $transform->getAttribute('Algorithm');
            if ($algorithm === Algorithms::ENVELOPED) {
                if ($signature !== null) {
                    $query .= '[count(ancestor-or-self::node() | ' . self::positionalPath($signature) . ')'
                        . ' > count(ancestor-or-self::node())]';
                }
            } elseif ($algorithm === Algorithms::XPATH) {
                $element = self::childrenByName($transform, 'XPath')[0] ?? null;
                if ($element === null) {
                    throw new SignatureException(
                        'The signature element with the transforms of the reference was not found in the XML to validate.'
                    );
                }
                $expression = $element->textContent;
                if (preg_match('/\bhere\s*\(\s*\)/', $expression) === 1) {
                    if (!$here) {
                        throw new SignatureException(
                            'The XPath of a reference to a resource that is not in the document can not use here().'
                        );
                    }
                    $expression = (string) preg_replace(
                        '/\bhere\s*\(\s*\)/',
                        '(' . self::positionalPath($element) . ')',
                        $expression
                    );
                }
                $query .= '[boolean(' . $expression . ')]';
                $namespaces += self::namespaces($element);
            }
        }

        return XmlHelper::canonicalize(
            $doc->getDomDocument(),
            $exclusive,
            $withComments,
            ['query' => $query, 'namespaces' => $namespaces]
        );
    }

    /**
     * Tells if the transforms canonicalize with the exclusive algorithm and if
     * they keep the comments.
     *
     * @param list<string> $algorithms
     * @return array{bool, bool}
     */
    private static function flags(array $algorithms): array
    {
        $exclusive = false;
        $withComments = false;
        foreach (Algorithms::CANONICALIZATIONS as $canonicalization) {
            if (in_array($canonicalization['uri'], $algorithms, true)) {
                $exclusive = $exclusive || $canonicalization['exclusive'];
                $withComments = $withComments || $canonicalization['comments'];
            }
        }

        return [$exclusive, $withComments];
    }

    /**
     * Gives a copy of the document without the signature. The copy is another
     * document: the one that is given is not changed, so the data of the next
     * reference is made from the document as it was.
     *
     * The copy has the signature in the same position as the original has it.
     */
    private static function copyWithoutSignature(XmlDocument $doc, ?DOMElement $signature): DOMDocument
    {
        $loaded = new XmlDocument();
        $loaded->loadXml($doc->saveXml());
        $copy = $loaded->getDomDocument();

        if ($signature !== null) {
            $element = self::find($copy, self::positionalPath($signature));
            $parent = $element?->parentNode;
            if ($element !== null && $parent !== null) {
                $parent->removeChild($element);
            }
        }

        return $copy;
    }

    /**
     * Finds an element of a document by its positional path.
     */
    private static function find(DOMDocument $doc, string $path): ?DOMNode
    {
        $nodes = (new DOMXPath($doc))->query($path);
        $node = $nodes !== false ? $nodes->item(0) : null;

        return $node instanceof DOMNode ? $node : null;
    }

    /**
     * Indicates if a node is an ancestor of another one, or the same one.
     */
    private static function contains(DOMNode $ancestor, DOMNode $node): bool
    {
        for ($current = $node; $current !== null; $current = $current->parentNode) {
            if ($current->isSameNode($ancestor)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Gives the child elements of an element with a local name.
     *
     * @return list<DOMElement>
     */
    public static function childrenByName(DOMElement $element, string $name): array
    {
        $children = [];
        foreach ($element->childNodes as $child) {
            if ($child instanceof DOMElement && $child->localName === $name) {
                $children[] = $child;
            }
        }

        return $children;
    }

    /**
     * Gives the path of an element from the root with the position of each
     * element among its sibling elements (`/*[1]/*[3]`), that does not depend on
     * namespaces.
     */
    public static function positionalPath(DOMNode $node): string
    {
        $path = '';
        for ($current = $node; $current instanceof DOMElement; $current = $current->parentNode) {
            $position = 1;
            for ($sibling = $current->previousSibling; $sibling !== null; $sibling = $sibling->previousSibling) {
                if ($sibling instanceof DOMElement) {
                    $position++;
                }
            }
            $path = '/*[' . $position . ']' . $path;
        }

        return $path;
    }

    /**
     * Gives the namespaces that are in scope in an element, by prefix.
     *
     * @return array<string, string>
     */
    private static function namespaces(DOMElement $element): array
    {
        $namespaces = [];
        $nodes = (new DOMXPath($element->ownerDocument ?? new DOMDocument()))->query('namespace::*', $element);
        foreach ($nodes !== false ? $nodes : [] as $node) {
            if ($node instanceof DOMNameSpaceNode && $node->prefix !== '' && $node->prefix !== 'xml') {
                $namespaces[$node->prefix] = $node->namespaceURI ?? '';
            }
        }

        return $namespaces;
    }
}
