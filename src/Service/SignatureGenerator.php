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

use Derafu\Array\ArrayReader;
use Derafu\Certificate\Contract\CertificateInterface;
use Derafu\Certificate\Contract\OpenSslInterface;
use Derafu\Certificate\Exception\CertificateException;
use Derafu\Certificate\Service\OpenSsl;
use Derafu\Config\Contract\OptionsInterface;
use Derafu\Signature\Contract\ResourceResolverInterface;
use Derafu\Signature\Contract\SignatureGeneratorInterface;
use Derafu\Signature\Exception\SignatureException;
use Derafu\Signature\Signature;
use Derafu\Signature\Support\Algorithms;
use Derafu\Signature\Support\RawSignature;
use Derafu\Signature\Support\ReferenceData;
use Derafu\Signature\Support\ReferenceTarget;
use Derafu\Signature\Support\SignatureElements;
use Derafu\Signature\Support\SignatureOptions;
use Derafu\Translation\Exception\Core\TranslatableLogicException as LogicException;
use Derafu\Xml\Contract\XmlDocumentInterface;
use Derafu\Xml\Contract\XmlServiceInterface;
use Derafu\Xml\Exception\XmlException;
use Derafu\Xml\XmlDocument;
use Derafu\Xml\XmlHelper;
use DOMElement;
use DOMNode;
use DOMXPath;

/**
 * Class that handles the generation of electronic signatures, particularly for
 * XML documents.
 */
final class SignatureGenerator implements SignatureGeneratorInterface
{
    /**
     * Constructor of the signature generator.
     *
     * @param XmlServiceInterface $xmlService
     */
    public function __construct(
        private readonly XmlServiceInterface $xmlService,
        private readonly OpenSslInterface $openSsl = new OpenSsl()
    ) {
    }

    /**
     * {@inheritDoc}
     */
    public function sign(
        string $data,
        string $privateKey,
        string|int $signatureAlgorithm = OPENSSL_ALGO_SHA1
    ): string {
        // Sign the data. If the data could not be signed, an exception is
        // thrown, with the errors of OpenSSL of that call.
        try {
            $signature = $this->openSsl->sign(
                $data,
                $privateKey,
                $signatureAlgorithm
            );
        } catch (CertificateException $e) {
            throw new SignatureException(
                'Could not sign the data.',
                previous: $e,
                errors: $e->getErrors()
            );
        }

        // Return the signature in base64.
        return base64_encode($signature);
    }

    /**
     * {@inheritDoc}
     *
     * The document is signed as it is given, and its format is not changed: the
     * spaces between its elements are part of what is signed. A string is signed
     * as it is. An `XmlDocumentInterface` is signed as it is saved by
     * `saveXml()`, with its own format settings, so whoever has the object is
     * the one that decides if the document has format (see
     * `XmlDocumentInterface::setFormatOutput()`).
     *
     * The returned XML is the document with the signature, written again by the
     * XML library, so it can differ from the given one in things that do not
     * change the meaning of the XML nor the validity of the signature: the XML
     * declaration is added or normalized, there is a line break at the end, an
     * empty element is written as `<a/>`, the attributes of an element are
     * written in one line with double quotes, and the character references can
     * be written in another form. This can change in the future, without
     * changing how the document is signed nor its validity.
     *
     * The options that are not given have the value that the signature always
     * had: one reference (the whole document without the signature, or the
     * element of the `reference`) with SHA-1, RSA with SHA-1, the inclusive
     * canonicalization, and the signature as the last child of the root
     * element. With `references` the digests are made with the signature in
     * its place in the document, as it is validated.
     *
     * Without `reference` and without `references`, if the document already has
     * a signature, the first one is not in the returned XML: it is removed from
     * the document before the digest is calculated, and the new signature is
     * the only one. With `reference` or `references` the signatures that the
     * document has are kept, and the new one is added.
     */
    public function signXml(
        XmlDocumentInterface|string $xml,
        CertificateInterface $certificate,
        array|OptionsInterface $options = []
    ): string {
        // The options are valid only for this signature.
        $settings = SignatureOptions::resolve($options);

        // If an Xml object is passed, it is converted to a string as the object
        // saves it, with its own format settings: the document that is signed
        // is the one that the user has, and its format is not changed.
        if (!is_string($xml)) {
            $xml = $xml->saveXml();
        }

        // Load the XML that will be signed.
        $doc = new XmlDocument();
        $doc->loadXml($xml);
        $rootElement = $doc->requireDocumentElement();

        // The data of the reference of the signature, when it is the short form
        // of one reference. It is made over the document as it is, before the
        // signature is in it.
        $legacyData = $settings->references === null
            ? $this->getReferenceData($doc, $settings->reference)
            : null;

        // Add the placeholder of the signature, where the XML signature goes.
        $name = 'DerafuSignature' . bin2hex(random_bytes(8));
        $placeholder = $doc->getDomDocument()->createElement($name);
        $this->place($doc, $rootElement, $placeholder, $settings->location);

        return $this->signTemplate(
            $name,
            ReferenceData::positionalPath($placeholder),
            $doc->saveXml(),
            $certificate,
            $settings,
            $legacyData
        );
    }

    /**
     * {@inheritDoc}
     *
     * The signature is the whole document: the references to an `Id` point to
     * its `Object` elements, and the ones that have another `URI` are the
     * resources that the resolver gives.
     */
    public function signXmlDetached(
        CertificateInterface $certificate,
        array|OptionsInterface $options
    ): string {
        $settings = SignatureOptions::resolve($options, detached: true);

        $name = 'DerafuSignature' . bin2hex(random_bytes(8));
        $doc = new XmlDocument();
        $doc->loadXml('<' . $name . '/>');

        return $this->signTemplate(
            $name,
            '/*[1]',
            $doc->saveXml(),
            $certificate,
            $settings,
            null
        );
    }

    /**
     * {@inheritDoc}
     */
    public function generateXmlDigestValue(
        XmlDocumentInterface $doc,
        ?string $reference = null
    ): string {
        return base64_encode(sha1($this->getReferenceData($doc, $reference), true));
    }

    /**
     * Gives the data that is digested in the short form of a reference.
     *
     * @param XmlDocumentInterface $doc XML document to be signed.
     * @param string|null $reference The `Id` of the element. If there is none,
     * it is the whole document.
     * @return string The data in C14N format.
     * @throws XmlException If the reference is not found in the XML.
     */
    private function getReferenceData(XmlDocumentInterface $doc, ?string $reference): string
    {
        // The digest will be made of a specific reference (ID) in the XML.
        if (!empty($reference)) {
            $node = ReferenceTarget::find($doc, $reference);
            if (!$node instanceof DOMNode) {
                throw new XmlException([
                    'No element with ID "{id}" was found in the XML document.',
                    'id' => ltrim($reference, '#'),
                ]);
            }

            return XmlHelper::canonicalize($node);
        }

        // When there is no reference, the digest is over the entire XML.
        // If the XML already has a "Signature" node within the root node, it
        // must be removed before obtaining its C14N.
        $docClone = clone $doc;
        $rootElement = $docClone->getDocumentElement();
        if ($rootElement === null) {
            throw new SignatureException(
                'Could not get the documentElement from the XML to sign (possible malformed XML).'
            );
        }
        $signatureElement = SignatureElements::find($docClone)[0] ?? null;
        if ($signatureElement !== null) {
            $signatureElement->parentNode?->removeChild($signatureElement);
        }

        return $docClone->C14N();
    }

    /**
     * Places the placeholder of the signature in the document.
     *
     * @param array{xpath: string, namespaces: array<string, string>, position: string}|null $location
     * Where to place it. If it is `null`, as the last child of the root.
     * @throws SignatureException If the location is not valid for the document.
     */
    private function place(
        XmlDocument $doc,
        DOMElement $rootElement,
        DOMElement $placeholder,
        ?array $location
    ): void {
        if ($location === null) {
            $rootElement->appendChild($placeholder);

            return;
        }

        $xpath = new DOMXPath($doc->getDomDocument());
        foreach ($location['namespaces'] as $prefix => $namespace) {
            $xpath->registerNamespace($prefix, $namespace);
        }
        $internalErrors = libxml_use_internal_errors(true);
        $nodes = $xpath->query($location['xpath']);
        libxml_clear_errors();
        libxml_use_internal_errors($internalErrors);
        if ($nodes === false) {
            throw new SignatureException([
                'The XPath "{xpath}" of the location of the signature is not valid.',
                'xpath' => $location['xpath'],
            ]);
        }

        $elements = [];
        foreach ($nodes as $node) {
            if ($node instanceof DOMElement) {
                $elements[] = $node;
            }
        }
        if (count($elements) !== 1) {
            throw new SignatureException([
                'The XPath "{xpath}" of the location of the signature selects {count} elements, and it must select one.',
                'xpath' => $location['xpath'],
                'count' => count($elements),
            ]);
        }
        $target = $elements[0];

        switch ($location['position']) {
            case 'first_child':
                $target->insertBefore($placeholder, $target->firstChild);
                break;
            case 'before':
            case 'after':
                $parent = $target->parentNode;
                if (!$parent instanceof DOMElement) {
                    throw new SignatureException(
                        'The signature can not be placed before or after the root element.'
                    );
                }
                $parent->insertBefore(
                    $placeholder,
                    $location['position'] === 'before' ? $target : $target->nextSibling
                );
                break;
            default:
                $target->appendChild($placeholder);
        }
    }

    /**
     * Builds the signature in the template of the document and signs it.
     *
     * The digests of the references are made, and then the `SignedInfo` is
     * signed, with the signature in its place in the document: the data of each
     * one is read from the signature as the validator reads it, so the
     * signature is validated with the same data that it was made with.
     *
     * @param string $name Name of the placeholder element of the template.
     * @param string $path Positional path of the placeholder in the template.
     * @param string $template XML of the document with the placeholder where
     * the signature goes.
     * @param string|null $legacyData Data of the reference, when the options
     * have the short form of one reference.
     * @return string The XML of the document with the signature.
     */
    private function signTemplate(
        string $name,
        string $path,
        string $template,
        CertificateInterface $certificate,
        SignatureOptions $settings,
        ?string $legacyData
    ): string {
        $signature = $this->createSignature($certificate, $settings);
        $objects = $settings->objects;
        $tag = '<' . $name . '/>';

        // The short form of one reference: it is the one that the signature
        // always had.
        if ($settings->references === null) {
            $reference = $settings->reference;
            $references = [[
                'uri' => $reference ? '#' . ltrim($reference, '#') : '',
                'id' => null,
                'type' => null,
                'digest' => $settings->digestAlgorithm,
                'transforms' => [[
                    'algorithm' => $reference ? Algorithms::C14N : Algorithms::ENVELOPED,
                    'expression' => null,
                    'namespaces' => [],
                ]],
            ]];
            $digests = [$this->digest($settings->digestAlgorithm, (string) $legacyData)];
        } else {
            $references = $settings->references;
            $digests = array_map(static fn (): string => '', $references);
        }
        $this->setReferences($signature, $references, $digests);
        $this->setObjects($signature, $objects);

        // The references that are made with the signature in the document.
        if ($settings->references !== null) {
            $context = $this->loadContext($template, $tag, $this->render($signature, $objects));
            $signatureElement = $this->requireElement($context, $path);
            $elements = $this->getReferenceElements($signatureElement);
            $digests = [];
            foreach ($references as $index => $reference) {
                $element = $elements[$index] ?? null;
                $algorithms = $element !== null ? ReferenceData::algorithms($element) : [];
                $data = ReferenceData::isExternal($reference['uri'])
                    ? ReferenceData::canonicalizeExternal(
                        $this->requireResolver($settings)->resolve($reference['uri']),
                        $element,
                        $algorithms
                    )
                    : ReferenceData::canonicalize($context, $signatureElement, $element, $reference['uri'], $algorithms);
                $digests[] = $this->digest($reference['digest'], $data);
            }
            $this->setReferences($signature, $references, $digests);
        }

        // The `SignedInfo` as it is in the document with the signature.
        $context = $this->loadContext($template, $tag, $this->render($signature, $objects));
        $signedInfo = ReferenceData::childrenByName($this->requireElement($context, $path), 'SignedInfo')[0] ?? null;
        $signedInfo instanceof DOMNode || throw new LogicException('SignedInfo node is missing from the generated Signature XML.');
        $c14n = XmlHelper::canonicalize(
            $signedInfo,
            Algorithms::CANONICALIZATIONS[$settings->canonicalizationMethod]['exclusive']
        );

        // Assign the calculated signature to the signature node.
        $signature->setSignatureValue(
            $this->signSignedInfo($c14n, $certificate, $settings->signatureAlgorithm)
        );

        // Add the XML signature in its place in the document.
        return str_replace($tag, $this->render($signature, $objects), $template);
    }

    /**
     * Creates the signature node with the data that does not depend on the
     * references.
     *
     * @throws LogicException If the certificate has no data.
     */
    private function createSignature(
        CertificateInterface $certificate,
        SignatureOptions $settings
    ): Signature {
        $signature = (new Signature())->configureSignatureData(
            digestValue: '',
            certificate: $certificate,
            signatureNamespace: $settings->signatureNamespace,
            includeCertificateChain: $settings->includeCertificateChain,
            signaturePrefix: $settings->signaturePrefix
        );

        // Validate that the digital certificate is assigned.
        if ($signature->getX509Certificate() === null) {
            throw new LogicException(
                'It is not possible to generate the signature of the Signature node if the digital certificate is not assigned.'
            );
        }

        $signature
            ->setSignatureMethod(Algorithms::SIGNATURES[$settings->signatureAlgorithm]['uri'])
            ->setCanonicalizationMethod(Algorithms::CANONICALIZATIONS[$settings->canonicalizationMethod]['uri'])
        ;
        if ($settings->signatureId !== null) {
            $signature->setSignatureId($settings->signatureId);
        }
        if ($settings->signatureValueId !== null) {
            $signature->setSignatureValueId($settings->signatureValueId);
        }

        return $signature;
    }

    /**
     * Sets the references with their digests in the signature.
     *
     * @param list<array{uri: string, id: string|null, type: string|null, digest: string, transforms: list<array{algorithm: string, expression: string|null, namespaces: array<string, string>}>}> $references
     * @param list<string> $digests Digest of each reference.
     */
    private function setReferences(Signature $signature, array $references, array $digests): void
    {
        $nodes = [];
        foreach ($references as $index => $reference) {
            $nodes[] = [
                'uri' => $reference['uri'],
                'id' => $reference['id'],
                'type' => $reference['type'],
                'digestAlgorithm' => Algorithms::DIGESTS[$reference['digest']]['uri'],
                'digestValue' => $digests[$index],
                'transforms' => $reference['transforms'],
            ];
        }
        $signature->setReferences($nodes);
    }

    /**
     * Sets the objects in the signature, with a text where its XML goes.
     *
     * @param list<array{xml: string, id: string|null, mimeType: string|null, encoding: string|null}> $objects
     */
    private function setObjects(Signature $signature, array $objects): void
    {
        if ($objects === []) {
            return;
        }

        $nodes = [];
        foreach ($objects as $index => $object) {
            $nodes[] = [
                'id' => $object['id'],
                'mimeType' => $object['mimeType'],
                'encoding' => $object['encoding'],
                'content' => $this->objectMarker($index),
            ];
        }
        $signature->setObjects($nodes);
    }

    /**
     * Gives the text that is in the place of the XML of an object until the
     * signature is written.
     */
    private function objectMarker(int $index): string
    {
        return '@@derafu-signature-object-' . $index . '@@';
    }

    /**
     * Writes the XML of the signature, with the XML of its objects.
     *
     * @param list<array{xml: string, id: string|null, mimeType: string|null, encoding: string|null}> $objects
     */
    private function render(Signature $signature, array $objects): string
    {
        $xml = $this->xmlService->encode($signature->getData());
        $xml->setFormatOutput(false);
        $signature->setXml($xml);
        $text = $xml->getXml();

        foreach ($objects as $index => $object) {
            $text = str_replace($this->objectMarker($index), $object['xml'], $text);
        }

        return $text;
    }

    /**
     * Loads the document with the signature in its place.
     */
    private function loadContext(string $template, string $tag, string $signature): XmlDocument
    {
        $context = new XmlDocument();
        $context->loadXml(str_replace($tag, $signature, $template));

        return $context;
    }

    /**
     * Finds the element of the signature in the document.
     *
     * @throws LogicException If it is not there.
     */
    private function requireElement(XmlDocument $doc, string $path): DOMElement
    {
        $nodes = (new DOMXPath($doc->getDomDocument()))->query($path);
        $element = $nodes !== false ? $nodes->item(0) : null;

        return $element instanceof DOMElement
            ? $element
            : throw new LogicException('SignedInfo node is missing from the generated Signature XML.');
    }

    /**
     * Gives the `Reference` elements of a signature.
     *
     * @return list<DOMElement>
     */
    private function getReferenceElements(DOMElement $signature): array
    {
        $signedInfo = ReferenceData::childrenByName($signature, 'SignedInfo')[0] ?? null;

        return $signedInfo !== null ? ReferenceData::childrenByName($signedInfo, 'Reference') : [];
    }

    /**
     * Gives the resolver of the resources that are not in the document.
     *
     * @throws SignatureException If there is none.
     */
    private function requireResolver(SignatureOptions $settings): ResourceResolverInterface
    {
        return $settings->resourceResolver ?? throw new SignatureException(
            'The signature has a reference to a resource that is not in the document, and it has no resource resolver.'
        );
    }

    /**
     * Calculates the digest of some data.
     *
     * @param string $algorithm Name of the digest algorithm.
     * @return string The digest in base64.
     */
    private function digest(string $algorithm, string $data): string
    {
        return base64_encode(hash(Algorithms::DIGESTS[$algorithm]['hash'], $data, true));
    }

    /**
     * Signs the canonical `SignedInfo` with the algorithm of the signature.
     *
     * The signatures of ECDSA and DSA, that OpenSSL gives as DER, are written
     * as the concatenation of their two integers, as XML Signature says.
     *
     * @param string $algorithm Name of the algorithm of the signature.
     * @return string The signature in base64.
     * @throws SignatureException If the algorithm is not the one of the key of
     * the certificate, or the signature could not be made.
     */
    private function signSignedInfo(
        string $c14n,
        CertificateInterface $certificate,
        string $algorithm
    ): string {
        $data = Algorithms::SIGNATURES[$algorithm];
        $details = ArrayReader::fromArray($certificate->getPublicKeyDetails());
        if ($details->getInt('type') !== $data['key']) {
            throw new SignatureException([
                'The signature algorithm "{algorithm}" is not the one of the type of key of the certificate.',
                'algorithm' => $algorithm,
            ]);
        }

        $signature = $this->sign($c14n, $certificate->getPrivateKey(), $data['openssl']);
        if ($data['key'] === OPENSSL_KEYTYPE_RSA) {
            return $signature;
        }

        // The size of each integer: the one of the order of the group.
        $size = $data['key'] === OPENSSL_KEYTYPE_EC
            ? intdiv($details->requireInt('bits') + 7, 8)
            : strlen($details->getReader('dsa')?->getString('q') ?? '');

        return base64_encode(RawSignature::fromDer((string) base64_decode($signature, true), $size));
    }
}
