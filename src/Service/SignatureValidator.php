<?php

declare(strict_types=1);

/**
 * Derafu: Signature - Library for digital signatures.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Signature\Service;

use Derafu\Certificate\AsymmetricKeyHelper;
use Derafu\Certificate\Contract\OpenSslInterface;
use Derafu\Certificate\Exception\CertificateException;
use Derafu\Certificate\Service\OpenSsl;
use Derafu\Signature\Contract\SignatureGeneratorInterface;
use Derafu\Signature\Contract\SignatureInterface;
use Derafu\Signature\Contract\SignatureValidatorInterface;
use Derafu\Signature\Exception\SignatureException;
use Derafu\Signature\Signature;
use Derafu\Signature\SignatureValidationResult;
use Derafu\Signature\Support\ReferenceTarget;
use Derafu\Signature\Support\SignatureElements;
use Derafu\Xml\Contract\XmlDocumentInterface;
use Derafu\Xml\Contract\XmlServiceInterface;
use Derafu\Xml\Exception\XmlException;
use Derafu\Xml\XmlDocument;
use Derafu\Xml\XmlHelper;
use DOMDocument;
use DOMElement;
use DOMNameSpaceNode;
use DOMNode;
use DOMXPath;

/**
 * Class that handles the validation of electronic signatures.
 */
final class SignatureValidator implements SignatureValidatorInterface
{
    private const string SHA1 = 'http://www.w3.org/2000/09/xmldsig#sha1';

    private const string TRANSFORM_ENVELOPED = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';

    private const string TRANSFORM_XPATH = 'http://www.w3.org/TR/1999/REC-xpath-19991116';

    /**
     * Transforms that canonicalize with the exclusive algorithm.
     */
    private const array TRANSFORMS_EXCLUSIVE = [
        'http://www.w3.org/2001/10/xml-exc-c14n#',
        'http://www.w3.org/2001/10/xml-exc-c14n#WithComments',
    ];

    /**
     * Transforms that canonicalize keeping the comments.
     */
    private const array TRANSFORMS_WITH_COMMENTS = [
        'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments',
        'http://www.w3.org/2001/10/xml-exc-c14n#WithComments',
    ];

    /**
     * Hash algorithms of the digest of the references, by URI.
     */
    private const array DIGEST_ALGORITHMS = [
        self::SHA1 => 'sha1',
        'http://www.w3.org/2001/04/xmlenc#sha256' => 'sha256',
        'http://www.w3.org/2001/04/xmldsig-more#sha384' => 'sha384',
        'http://www.w3.org/2001/04/xmlenc#sha512' => 'sha512',
    ];

    /**
     * Algorithms of the signature of the `SignedInfo`, by URI.
     */
    private const array SIGNATURE_ALGORITHMS = [
        'http://www.w3.org/2000/09/xmldsig#rsa-sha1' => OPENSSL_ALGO_SHA1,
        'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256' => OPENSSL_ALGO_SHA256,
        'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384' => OPENSSL_ALGO_SHA384,
        'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512' => OPENSSL_ALGO_SHA512,
    ];

    public function __construct(
        private readonly SignatureGeneratorInterface $generator,
        private readonly XmlServiceInterface $xmlService,
        private readonly OpenSslInterface $openSsl = new OpenSsl()
    ) {
    }

    /**
     * {@inheritDoc}
     */
    public function validate(
        string $data,
        string $signature,
        string $certificate,
        string|int $signatureAlgorithm = OPENSSL_ALGO_SHA1
    ): bool {
        $certificate = AsymmetricKeyHelper::normalizeCertificate($certificate);

        // A signature that is not valid is a result (`false`). A failure of the
        // verification itself is an exception, with the errors of OpenSSL of
        // that call.
        try {
            return $this->openSsl->verify(
                $data,
                (string) base64_decode($signature),
                $certificate,
                $signatureAlgorithm
            );
        } catch (CertificateException $e) {
            throw new SignatureException(
                'An error occurred while verifying the electronic signature of the data.',
                previous: $e,
                errors: $e->getErrors()
            );
        }
    }

    /**
     * {@inheritDoc}
     *
     * The format of the document is not changed: a string is validated as it
     * is, and an `XmlDocumentInterface` as it is saved by `saveXml()`, with its
     * own format settings. If the format of the document is not the one that it
     * had when it was signed, its signature is not valid.
     */
    public function validateXml(XmlDocumentInterface|string $xml): array
    {
        // If a string is passed, it is loaded into an XML document.
        if (is_string($xml)) {
            $doc = new XmlDocument();
            $doc->loadXml($xml);
        }
        // If an Xml object is passed, it is used directly.
        else {
            $doc = $xml;
        }

        // The XML must have a document element, where the signatures are.
        $rootElement = $doc->getDocumentElement();
        if ($rootElement === null) {
            throw new SignatureException(
                'Could not get the documentElement from the XML to validate its signature (possible malformed XML).'
            );
        }

        // Search for all elements that are tag Signature.
        // An XML document can have more than one signature.
        $elements = SignatureElements::find($doc);

        // If no signatures are found in the XML, an error is thrown.
        if ($elements === []) {
            throw new SignatureException(
                'No signatures were found in the XML to validate.'
            );
        }

        // Single pass: parse and validate each signature node. If validation
        // fails, the error is captured in the result instead of throwing, so
        // callers can always inspect the signer's certificate data.
        $results = [];
        foreach ($elements as $signatureElement) {
            $result = null;
            $candidates = [
                XmlHelper::canonicalize($signatureElement),
                ...$this->canonicalizeWithinAncestors($signatureElement),
            ];
            foreach ($candidates as $candidate) {
                $signatureNode = $this->createSignatureNode($candidate);

                $error = null;
                try {
                    $this->validateXmlDigestValue($doc, $signatureNode);
                    $this->validateXmlSignatureValue($signatureNode);
                } catch (SignatureException $e) {
                    $error = $e;
                }

                // The first one is the signature as it is in the document, and
                // the one that is reported if none of them is valid.
                $current = new SignatureValidationResult($signatureNode, $error);
                $result ??= $current;
                if ($error === null) {
                    $result = $current;
                    break;
                }
            }

            $results[] = $result;
        }

        return $results;
    }

    /**
     * {@inheritDoc}
     */
    public function createSignatureNode(string $xml): SignatureInterface
    {
        $signatureNode = new Signature();

        $signature = new XmlDocument();
        $signature->setFormatOutput(false);
        $signature->loadXml($xml);

        $data = $this->xmlService->decode($signature);

        // Important: The order is crucial, since setData() invalidates the Xml
        // if it was previously assigned.
        $signatureNode->setData($data);
        $signatureNode->setXml($signature);

        return $signatureNode;
    }

    /**
     * {@inheritDoc}
     */
    public function validateXmlDigestValue(
        XmlDocumentInterface|string $xml,
        SignatureInterface $signatureNode
    ): void {
        // If an Xml object is passed, it is converted to a string as the object
        // saves it, with its own format settings: the document that is
        // validated is the one that the user has, and its format is not
        // changed.
        if (!is_string($xml)) {
            $xml = $xml->saveXml();
        }

        // Load the string XML into an XML document.
        $doc = new XmlDocument();
        $doc->loadXml($xml);

        // A signature with several references, with a reference that is
        // processed with an XPath transform, or whose digest is not SHA1, is
        // validated reference by reference.
        $references = $signatureNode->getReferences();
        if (count($references) > 1 || ($references !== [] && $this->needsReferenceValidation($references[0]))) {
            $this->validateReferences($doc, $signatureNode, $references);

            return;
        }

        // Get the digest value that comes in the XML (in the signature node).
        $digestValueXml = $signatureNode->getDigestValue();
        if ($digestValueXml === null) {
            throw new SignatureException(
                'The DigestValue is missing from the signature node.'
            );
        }
        $reference = $signatureNode->getReference();

        // Calculate the digest value from the XML document.
        $digestValueCalculated = $this->generator->generateXmlDigestValue($doc, $reference);

        // If primary digest doesn't match and we have a reference, try alternative
        // C14N approaches used by different Chilean DTE signing systems:
        //   - Exclusive C14N (used by some commercial systems, e.g. CCG SPA)
        //   - Strip inherited namespaces + standard C14N (used by LibreDTE, SII official examples)
        if ($digestValueXml !== $digestValueCalculated && !empty($reference)) {
            $digestValueCalculated = $this->findMatchingDigestValue(
                $doc,
                $reference,
                $digestValueXml
            ) ?? $digestValueCalculated;
        }

        // If the digest values do not match, it is not valid.
        if ($digestValueXml !== $digestValueCalculated) {
            throw new SignatureException([
                'The DigestValue that comes in the XML "{xml}" for the reference "{reference}" does not match the calculated value when validating "{calculated}". The data of the reference could have been manipulated after being signed.',
                'xml' => $digestValueXml,
                'reference' => $reference,
                'calculated' => $digestValueCalculated,
            ]);
        }
    }

    /**
     * Validates the DigestValue of each reference of a signature.
     *
     * @param XmlDocument $doc Document to be validated.
     * @param SignatureInterface $signatureNode Signature node to be validated.
     * @param list<array{uri: string|null, digestMethod: string|null, digestValue: string|null, transforms: list<string>}> $references
     * @throws SignatureException If the DigestValue of any reference is invalid.
     */
    private function validateReferences(
        XmlDocument $doc,
        SignatureInterface $signatureNode,
        array $references
    ): void {
        $value = (string) preg_replace('/\s+/', '', (string) $signatureNode->getSignatureValue());

        foreach ($references as $index => $reference) {
            if ($reference['digestValue'] === null) {
                throw new SignatureException(
                    'The DigestValue is missing from the signature node.'
                );
            }
            $expected = (string) preg_replace('/\s+/', '', $reference['digestValue']);
            $algorithm = $this->getDigestAlgorithm($reference['digestMethod']);

            $calculated = null;
            foreach ($this->canonicalizeReference($doc, $value, $index, $reference) as $c14n) {
                $hash = base64_encode(hash($algorithm, $c14n, true));
                $calculated ??= $hash;
                if ($hash === $expected) {
                    $calculated = $hash;
                    break;
                }
            }

            if ($calculated !== $expected) {
                throw new SignatureException([
                    'The DigestValue that comes in the XML "{xml}" for the reference "{reference}" does not match the calculated value when validating "{calculated}". The data of the reference could have been manipulated after being signed.',
                    'xml' => $expected,
                    'reference' => $reference['uri'] ?? '',
                    'calculated' => $calculated ?? '',
                ]);
            }
        }
    }

    /**
     * Indicates if a reference can not be validated with the SHA1 digest of the
     * element it points to: it has an XPath transform or another digest
     * algorithm.
     *
     * @param array{uri: string|null, digestMethod: string|null, digestValue: string|null, transforms: list<string>} $reference
     */
    private function needsReferenceValidation(array $reference): bool
    {
        return $this->hasXPathTransform($reference)
            || ($reference['digestMethod'] !== null && $reference['digestMethod'] !== self::SHA1);
    }

    /**
     * Indicates if a reference is processed with an XPath transform.
     *
     * @param array{uri: string|null, digestMethod: string|null, digestValue: string|null, transforms: list<string>} $reference
     */
    private function hasXPathTransform(array $reference): bool
    {
        return in_array(self::TRANSFORM_XPATH, $reference['transforms'], true);
    }

    /**
     * Gives the hash algorithm of the `DigestMethod` of a reference.
     *
     * @param string|null $algorithm The URI of the algorithm. If it is not
     * defined, SHA1 is used, as in the rest of the validation.
     * @throws SignatureException If the algorithm is not supported.
     */
    private function getDigestAlgorithm(?string $algorithm): string
    {
        if ($algorithm === null) {
            return 'sha1';
        }

        return self::DIGEST_ALGORITHMS[$algorithm] ?? throw new SignatureException([
            'The digest algorithm "{algorithm}" of the signature is not supported.',
            'algorithm' => $algorithm,
        ]);
    }

    /**
     * Finds, in a document, the signature element that has a `SignatureValue`.
     *
     * The signature node that is validated is a copy of the element, so the
     * element is the one with the same value.
     *
     * @param string $value The `SignatureValue`, without whitespace.
     */
    private function findSignatureElement(XmlDocument $doc, string $value): ?DOMElement
    {
        foreach (SignatureElements::find($doc) as $element) {
            $candidate = $this->childrenByName($element, 'SignatureValue')[0] ?? null;
            if ($candidate !== null && preg_replace('/\s+/', '', $candidate->textContent) === $value) {
                return $element;
            }
        }

        return null;
    }

    /**
     * Gives the child elements of an element with a local name.
     *
     * @return list<DOMElement>
     */
    private function childrenByName(DOMElement $element, string $name): array
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
     * Gives the canonicalizations of the data of a reference that can have its
     * digest, in the order to try them.
     *
     * The data is what the URI points to (the whole document, or an element),
     * after the transforms of the reference.
     *
     * @param string $value The `SignatureValue` of the signature, without
     * whitespace, to find its element in the document.
     * @param array{uri: string|null, digestMethod: string|null, digestValue: string|null, transforms: list<string>} $reference
     * @return iterable<string>
     * @throws SignatureException If the transforms need the signature element
     * and it is not in the document.
     * @throws XmlException If the element of the reference does not exist.
     */
    private function canonicalizeReference(
        XmlDocument $doc,
        string $value,
        int $index,
        array $reference
    ): iterable {
        $exclusive = false;
        $withComments = false;
        foreach ($reference['transforms'] as $transform) {
            $exclusive = $exclusive || in_array($transform, self::TRANSFORMS_EXCLUSIVE, true);
            $withComments = $withComments || in_array($transform, self::TRANSFORMS_WITH_COMMENTS, true);
        }

        $uri = $reference['uri'];
        $target = null;
        if ($uri !== null) {
            $target = ReferenceTarget::find($doc, $uri);
            if (!$target instanceof DOMNode) {
                throw new XmlException([
                    'No element with ID "{id}" was found in the XML document.',
                    'id' => ltrim($uri, '#'),
                ]);
            }
        }

        // With an XPath transform the data is a set of nodes of the document.
        if ($this->hasXPathTransform($reference)) {
            yield $this->canonicalizeNodeSet(
                $doc,
                $this->findSignatureElement($doc, $value),
                $index,
                $target,
                $exclusive,
                $withComments
            );

            return;
        }

        // The whole document, without the signature.
        if ($target === null) {
            $clone = clone $doc;
            $signature = $this->findSignatureElement($clone, $value);
            if ($signature !== null) {
                $signature->parentNode?->removeChild($signature);
            }

            yield $clone->C14N();

            return;
        }

        yield XmlHelper::canonicalize($target, $exclusive, $withComments);

        yield from $this->alternativeCanonicalizations($target);
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
     * @param int $index Position of the reference in the signature.
     * @param DOMNode|null $target Element of the reference, or `null` for the
     * whole document.
     * @throws SignatureException If the element of the signature is not in the
     * document, or the reference does not have the transforms it declares.
     */
    private function canonicalizeNodeSet(
        XmlDocument $doc,
        ?DOMElement $signature,
        int $index,
        ?DOMNode $target,
        bool $exclusive,
        bool $withComments
    ): string {
        $signedInfo = $signature !== null ? ($this->childrenByName($signature, 'SignedInfo')[0] ?? null) : null;
        $referenceElement = $signedInfo !== null ? ($this->childrenByName($signedInfo, 'Reference')[$index] ?? null) : null;
        $transforms = $referenceElement !== null ? ($this->childrenByName($referenceElement, 'Transforms')[0] ?? null) : null;
        if ($signature === null || $transforms === null) {
            throw new SignatureException(
                'The signature element with the transforms of the reference was not found in the XML to validate.'
            );
        }

        if ($target === null) {
            $nodes = '(//. | //@* | //namespace::*)';
        } else {
            $path = $this->getPositionalPath($target);
            $nodes = '(' . $path . '/descendant-or-self::node() | '
                . $path . '/descendant-or-self::*/@* | '
                . $path . '/descendant-or-self::*/namespace::*)';
        }

        $query = $nodes;
        $namespaces = [];
        foreach ($this->childrenByName($transforms, 'Transform') as $transform) {
            $algorithm = $transform->getAttribute('Algorithm');
            if ($algorithm === self::TRANSFORM_ENVELOPED) {
                $query .= '[count(ancestor-or-self::node() | ' . $this->getPositionalPath($signature) . ')'
                    . ' > count(ancestor-or-self::node())]';
            } elseif ($algorithm === self::TRANSFORM_XPATH) {
                $element = $this->childrenByName($transform, 'XPath')[0] ?? null;
                if ($element === null) {
                    throw new SignatureException(
                        'The signature element with the transforms of the reference was not found in the XML to validate.'
                    );
                }
                $expression = (string) preg_replace(
                    '/\bhere\s*\(\s*\)/',
                    '(' . $this->getPositionalPath($element) . ')',
                    $element->textContent
                );
                $query .= '[boolean(' . $expression . ')]';
                $namespaces += $this->getNamespaces($element);
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
     * Gives the path of an element from the root with the position of each
     * element among its sibling elements (`/*[1]/*[3]`), that does not depend on
     * namespaces.
     */
    private function getPositionalPath(DOMNode $node): string
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
    private function getNamespaces(DOMElement $element): array
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

    /**
     * Tries alternative C14N approaches to find one that matches the expected digest.
     *
     * Different Chilean DTE signing systems compute DigestValue using different
     * C14N variants. This method tries exclusive C14N and strip-inherited-namespaces
     * C14N and returns the matching value, or null if none matches.
     */
    private function findMatchingDigestValue(
        XmlDocument $doc,
        string $reference,
        string $expected
    ): ?string {
        $node = ReferenceTarget::find($doc, $reference);
        if (!$node instanceof DOMNode) {
            return null;
        }

        foreach ($this->alternativeCanonicalizations($node) as $c14n) {
            $hash = base64_encode(sha1($c14n, true));
            if ($hash === $expected) {
                return $hash;
            }
        }

        return null;
    }

    /**
     * Canonicalizations of an element that other signing systems use, besides
     * the standard C14N of the element in its document:
     *
     *   - Exclusive C14N (only includes visibly-utilized namespaces).
     *   - Strip inherited namespaces: serialize the node, remove all xmlns
     *     declarations (inherited from ancestors), re-parse, C14N. This matches
     *     how LibreDTE and the SII's official example DTE are signed.
     *   - The element as it was in the smaller document where it could have
     *     been signed: an element signed in its own document and embedded later
     *     in a larger one (like a certificate inside an envelope) inherits the
     *     namespaces of the new ancestors, which were not there when signing.
     *
     * @return iterable<string> The C14N of the element, in the order to try
     * them. Each one is built when it is requested.
     */
    private function alternativeCanonicalizations(DOMNode $node): iterable
    {
        yield XmlHelper::canonicalize($node, exclusive: true);

        $newDoc = new XmlDocument();
        $newDoc->getDomDocument()->appendChild($newDoc->getDomDocument()->importNode($node, true));
        $serialized = $newDoc->saveXml($newDoc->getDomDocument()->documentElement);
        $stripped = (string) preg_replace('/ xmlns(?::[^=]*)?\s*=\s*"[^"]*"/', '', $serialized);
        $stripped = '<?xml version="1.0" encoding="UTF-8"?>' . $stripped;
        $strippedDoc = new XmlDocument();
        if (@$strippedDoc->loadXml($stripped) && $strippedDoc->getDomDocument()->documentElement) {
            yield XmlHelper::canonicalize(
                $strippedDoc->getDomDocument()->documentElement
            );
        }

        yield from $this->canonicalizeWithinAncestors($node);
    }

    /**
     * Canonicalizes an element as if the document where it is were rooted in
     * each one of its ancestors, from the nearest one up to the child of the
     * root: only the namespaces declared down from that ancestor are in scope.
     *
     * @return list<string> The C14N of the element, one per ancestor.
     */
    private function canonicalizeWithinAncestors(DOMNode $node): array
    {
        $ancestors = [];
        for ($parent = $node->parentNode; $parent instanceof DOMElement; $parent = $parent->parentNode) {
            $ancestors[] = $parent;
        }
        // The last one is the root of the document: with it the result is the
        // C14N of the element in its own document, that was already tried.
        array_pop($ancestors);

        $results = [];
        foreach (array_keys($ancestors) as $depth) {
            $doc = new DOMDocument();
            $parent = $doc;
            for ($i = $depth; $i >= 0; $i--) {
                $copy = $doc->importNode($ancestors[$i], false);
                $parent->appendChild($copy);
                $parent = $copy;
            }
            $copy = $doc->importNode($node, true);
            $parent->appendChild($copy);
            $results[] = XmlHelper::canonicalize($copy);
        }

        return $results;
    }

    /**
     * {@inheritDoc}
     */
    public function validateXmlSignatureValue(
        SignatureInterface $signatureNode
    ): void {
        // Validate that SignatureValue is present.
        $signatureValue = $signatureNode->getSignatureValue();
        if ($signatureValue === null) {
            throw new SignatureException(
                'The SignatureValue is missing from the signature node.'
            );
        }

        // Validate that X509Certificate is present.
        $x509Certificate = $signatureNode->getX509Certificate();
        if ($x509Certificate === null) {
            throw new SignatureException(
                'The X509Certificate is missing from the signature node.'
            );
        }

        // Generate the string XML of the data that will be validated.
        // Standard C14N is tried first; exclusive C14N is used as fallback since
        // some signing systems (e.g. certain commercial DTE issuers) use it.
        $xpath = "//*[local-name()='Signature']/*[local-name()='SignedInfo']";
        $signedInfoNode = $signatureNode->getXml()->getNodes($xpath)->item(0);
        $signedInfoC14N = $signedInfoNode instanceof DOMNode
            ? XmlHelper::canonicalize($signedInfoNode)
            : $signatureNode->getXml()->C14NEncoded($xpath);

        // Validate the electronic signature, with the algorithm of its
        // `SignatureMethod` (SHA1 if it is not one that is known).
        $algorithm = self::SIGNATURE_ALGORITHMS[$signatureNode->getSignatureMethod() ?? ''] ?? OPENSSL_ALGO_SHA1;
        $isValid = $this->validate(
            $signedInfoC14N,
            $signatureValue,
            $x509Certificate,
            $algorithm
        );

        // If standard C14N fails, try exclusive C14N as fallback.
        if (!$isValid && $signedInfoNode instanceof DOMNode) {
            $signedInfoC14N = XmlHelper::canonicalize($signedInfoNode, exclusive: true);
            $isValid = $this->validate(
                $signedInfoC14N,
                $signatureValue,
                $x509Certificate,
                $algorithm
            );
        }

        // If it still fails, try the `SignedInfo` without the namespace
        // declarations of its first tag. Some signing systems, like the one
        // that signed the books of the SII certification, sign it as a
        // fragment that does not declare the prefix of its elements (the
        // `ds:` of `<ds:SignedInfo>`), and the SII accepts those signatures.
        if (!$isValid && $signedInfoNode instanceof DOMNode) {
            $signedInfoC14N = $this->removeNamespaceDeclarations(
                XmlHelper::canonicalize($signedInfoNode)
            );
            $isValid = $this->validate(
                $signedInfoC14N,
                $signatureValue,
                $x509Certificate,
                $algorithm
            );
        }

        // If the electronic signature is not valid, an exception is thrown.
        if (!$isValid) {
            throw new SignatureException([
                'The electronic signature of the `SignedInfo` node of the XML for the reference "{reference}" is not valid.',
                'reference' => $signatureNode->getReference(),
            ]);
        }
    }

    /**
     * Removes the namespace declarations of the first tag of a canonicalized
     * element.
     *
     * @param string $c14n Canonicalized XML of an element.
     * @return string The XML without the `xmlns` and `xmlns:prefix`
     * declarations of the first tag.
     */
    private function removeNamespaceDeclarations(string $c14n): string
    {
        return (string) preg_replace(
            '/^(<[^\s>\/]+)(?:\s+xmlns(?::[^\s=]+)?="[^"]*")+/',
            '$1',
            $c14n
        );
    }
}
