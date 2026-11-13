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
use Derafu\Config\Contract\OptionsInterface;
use Derafu\Signature\Contract\ResourceResolverInterface;
use Derafu\Signature\Contract\SignatureGeneratorInterface;
use Derafu\Signature\Contract\SignatureInterface;
use Derafu\Signature\Contract\SignatureValidatorInterface;
use Derafu\Signature\Exception\SignatureException;
use Derafu\Signature\Signature;
use Derafu\Signature\SignatureValidationResult;
use Derafu\Signature\Support\Algorithms;
use Derafu\Signature\Support\RawSignature;
use Derafu\Signature\Support\ReferenceData;
use Derafu\Signature\Support\ReferenceTarget;
use Derafu\Signature\Support\SignatureElements;
use Derafu\Signature\Support\SignatureOptions;
use Derafu\Xml\Contract\XmlDocumentInterface;
use Derafu\Xml\Contract\XmlServiceInterface;
use Derafu\Xml\Exception\XmlException;
use Derafu\Xml\XmlDocument;
use Derafu\Xml\XmlHelper;
use DOMDocument;
use DOMElement;
use DOMNode;

/**
 * Class that handles the validation of electronic signatures.
 */
final class SignatureValidator implements SignatureValidatorInterface
{
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
    public function validateXml(XmlDocumentInterface|string $xml, array|OptionsInterface $options = []): array
    {
        // The options are valid only for this validation.
        $resolver = SignatureOptions::resolveResolver($options);

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
        $elements = SignatureElements::find($doc, true);

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
                    $this->validateXmlDigestValue($doc, $signatureNode, ['resource_resolver' => $resolver]);
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
        SignatureInterface $signatureNode,
        array|OptionsInterface $options = []
    ): void {
        $resolver = SignatureOptions::resolveResolver($options);

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
        if (
            count($references) > 1
            || ($references !== [] && $this->needsReferenceValidation($doc, $references[0]))
            || ($references !== [] && $this->isWholeDocumentWithOtherSignatures($doc, $references[0]))
        ) {
            $this->validateReferences($doc, $signatureNode, $references, $resolver);

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
     * @param ResourceResolverInterface|null $resolver Gives the data of the
     * references to resources that are not in the document.
     * @throws SignatureException If the DigestValue of any reference is invalid.
     */
    private function validateReferences(
        XmlDocument $doc,
        SignatureInterface $signatureNode,
        array $references,
        ?ResourceResolverInterface $resolver
    ): void {
        $value = (string) preg_replace('/\s+/', '', (string) $signatureNode->getSignatureValue());
        $signature = $this->findSignatureElement($doc, $value);
        $signedInfo = $signature !== null ? (ReferenceData::childrenByName($signature, 'SignedInfo')[0] ?? null) : null;
        $elements = $signedInfo !== null ? ReferenceData::childrenByName($signedInfo, 'Reference') : [];

        foreach ($references as $index => $reference) {
            if ($reference['digestValue'] === null) {
                throw new SignatureException(
                    'The DigestValue is missing from the signature node.'
                );
            }
            $expected = (string) preg_replace('/\s+/', '', $reference['digestValue']);
            $algorithm = $this->getDigestAlgorithm($reference['digestMethod']);

            $calculated = null;
            foreach ($this->canonicalizeReference($doc, $signature, $elements[$index] ?? null, $reference, $resolver) as $c14n) {
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
     * element it points to: it has an XPath transform, the enveloped signature
     * transform in an element, it is a resource that is not in the document, or
     * it has another digest algorithm.
     *
     * @param array{uri: string|null, digestMethod: string|null, digestValue: string|null, transforms: list<string>} $reference
     */
    private function needsReferenceValidation(XmlDocument $doc, array $reference): bool
    {
        return $this->hasXPathTransform($reference)
            || ReferenceData::isExternalTo($doc, $reference['uri'])
            || ($reference['uri'] !== null && in_array(Algorithms::ENVELOPED, $reference['transforms'], true))
            || ($reference['digestMethod'] !== null && $reference['digestMethod'] !== Algorithms::DIGESTS['sha1']['uri']);
    }

    /**
     * Indicates if a reference is to the whole document and the document has
     * more than one signature.
     *
     * The data of the whole document is the document without the signature that
     * is validated, and only that one (XML Signature 1.1, section 6.6.4): the
     * other signatures are part of the data. The short form of one reference
     * leaves out the first signature of the document, which is the one that
     * is validated only if the document has one.
     *
     * @param array{uri: string|null, digestMethod: string|null, digestValue: string|null, transforms: list<string>} $reference
     */
    private function isWholeDocumentWithOtherSignatures(XmlDocument $doc, array $reference): bool
    {
        return ($reference['uri'] === null || $reference['uri'] === '')
            && count(SignatureElements::find($doc, true)) > 1;
    }

    /**
     * Indicates if a reference is processed with an XPath transform.
     *
     * @param array{uri: string|null, digestMethod: string|null, digestValue: string|null, transforms: list<string>} $reference
     */
    private function hasXPathTransform(array $reference): bool
    {
        return in_array(Algorithms::XPATH, $reference['transforms'], true);
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

        return Algorithms::hashByUri($algorithm) ?? throw new SignatureException([
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
        foreach (SignatureElements::find($doc, true) as $element) {
            $candidate = ReferenceData::childrenByName($element, 'SignatureValue')[0] ?? null;
            if ($candidate !== null && preg_replace('/\s+/', '', $candidate->textContent) === $value) {
                return $element;
            }
        }

        return null;
    }

    /**
     * Gives the canonicalizations of the data of a reference that can have its
     * digest, in the order to try them.
     *
     * The data is what the URI points to (the whole document, an element, or a
     * resource that is not in the document), after the transforms of the
     * reference.
     *
     * @param DOMElement|null $signature Element of the signature in the
     * document.
     * @param DOMElement|null $element Element `Reference` in the signature.
     * @param array{uri: string|null, digestMethod: string|null, digestValue: string|null, transforms: list<string>} $reference
     * @return iterable<string>
     * @throws SignatureException If the transforms need the signature element
     * and it is not in the document, or the resource is not in the document and
     * there is no resolver.
     * @throws XmlException If the element of the reference does not exist.
     */
    private function canonicalizeReference(
        XmlDocument $doc,
        ?DOMElement $signature,
        ?DOMElement $element,
        array $reference,
        ?ResourceResolverInterface $resolver
    ): iterable {
        $uri = $reference['uri'];

        // A resource that is not in the document.
        if (ReferenceData::isExternalTo($doc, $uri)) {
            if ($resolver === null) {
                throw new SignatureException([
                    'The reference "{reference}" points to a resource that is not in the document, and no resource resolver was given.',
                    'reference' => $uri,
                ]);
            }

            yield ReferenceData::canonicalizeExternal(
                $resolver->resolve((string) $uri),
                $element,
                $reference['transforms']
            );

            return;
        }

        yield ReferenceData::canonicalize($doc, $signature, $element, $uri, $reference['transforms']);

        // The data of an element that other signing systems canonicalize in
        // other ways.
        $target = ReferenceData::target($doc, $uri);
        if ($target !== null && !$this->hasXPathTransform($reference)) {
            yield from $this->alternativeCanonicalizations($target);
        }
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
        // `SignatureMethod` (SHA1 if it is not one that is known). The
        // signatures of ECDSA and DSA are written as the concatenation of
        // their two integers, and OpenSSL verifies them as DER.
        $method = Algorithms::signatureByUri($signatureNode->getSignatureMethod() ?? '');
        $algorithm = $method['openssl'] ?? OPENSSL_ALGO_SHA1;
        $value = $signatureValue;
        if ($method !== null && $method['key'] !== OPENSSL_KEYTYPE_RSA) {
            try {
                $value = base64_encode(RawSignature::toDer((string) base64_decode($signatureValue)));
            } catch (SignatureException) {
                $value = null;
            }
        }
        $isValid = $value !== null && $this->validate(
            $signedInfoC14N,
            $value,
            $x509Certificate,
            $algorithm
        );

        // If standard C14N fails, try exclusive C14N as fallback.
        if (!$isValid && $value !== null && $signedInfoNode instanceof DOMNode) {
            $signedInfoC14N = XmlHelper::canonicalize($signedInfoNode, exclusive: true);
            $isValid = $this->validate(
                $signedInfoC14N,
                $value,
                $x509Certificate,
                $algorithm
            );
        }

        // If it still fails, try the `SignedInfo` without the namespace
        // declarations of its first tag. Some signing systems, like the one
        // that signed the books of the SII certification, sign it as a
        // fragment that does not declare the prefix of its elements (the
        // `ds:` of `<ds:SignedInfo>`), and the SII accepts those signatures.
        if (!$isValid && $value !== null && $signedInfoNode instanceof DOMNode) {
            $signedInfoC14N = $this->removeNamespaceDeclarations(
                XmlHelper::canonicalize($signedInfoNode)
            );
            $isValid = $this->validate(
                $signedInfoC14N,
                $value,
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
