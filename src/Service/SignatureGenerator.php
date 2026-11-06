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

use Derafu\Certificate\Contract\CertificateInterface;
use Derafu\Certificate\Contract\OpenSslInterface;
use Derafu\Certificate\Exception\CertificateException;
use Derafu\Certificate\Service\OpenSsl;
use Derafu\Signature\Contract\SignatureGeneratorInterface;
use Derafu\Signature\Contract\SignatureInterface;
use Derafu\Signature\Exception\SignatureException;
use Derafu\Signature\Signature;
use Derafu\Signature\Support\ReferenceTarget;
use Derafu\Signature\Support\SignatureElements;
use Derafu\Translation\Exception\Core\TranslatableLogicException as LogicException;
use Derafu\Xml\Contract\XmlDocumentInterface;
use Derafu\Xml\Contract\XmlServiceInterface;
use Derafu\Xml\Exception\XmlException;
use Derafu\Xml\XmlDocument;
use Derafu\Xml\XmlHelper;
use DOMNode;

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
     */
    public function signXml(
        XmlDocumentInterface|string $xml,
        CertificateInterface $certificate,
        ?string $reference = null,
        ?string $signatureNamespace = null,
        bool $includeCertificateChain = false,
        ?string $signaturePrefix = null
    ): string {
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

        // Generate the "DigestValue" of the reference data.
        $digestValue = $this->generateXmlDigestValue($doc, $reference);

        // Create the instance that represents the signature node with its data.
        $signatureNode = (new Signature())->configureSignatureData(
            reference: $reference,
            digestValue: $digestValue,
            certificate: $certificate,
            signatureNamespace: $signatureNamespace,
            includeCertificateChain: $includeCertificateChain,
            signaturePrefix: $signaturePrefix
        );

        // Add the placeholder of the signature in the root node, where the XML
        // signature goes.
        $signatureElement = $doc->getDomDocument()->createElement('Signature', '');
        $rootElement->appendChild($signatureElement);
        $xmlTemplate = $doc->saveXml();

        // Sign the document by calculating the value of the signature of the
        // `Signature` node.
        $signatureNode = $this->signSignature(
            $signatureNode,
            $certificate,
            $xmlTemplate
        );
        $xmlSignature = $signatureNode->getXml()->getXml();

        // Add the XML signature in the Signature node.
        $xmlSigned = str_replace('<Signature/>', $xmlSignature, $xmlTemplate);

        // Return the string XML of the signed XML document.
        return $xmlSigned;
    }

    /**
     * {@inheritDoc}
     */
    public function generateXmlDigestValue(
        XmlDocumentInterface $doc,
        ?string $reference = null
    ): string {
        // The digest will be made of a specific reference (ID) in the XML.
        if (!empty($reference)) {
            $node = ReferenceTarget::find($doc, $reference);
            if (!$node instanceof DOMNode) {
                throw new XmlException([
                    'No element with ID "{id}" was found in the XML document.',
                    'id' => ltrim($reference, '#'),
                ]);
            }
            $dataToDigest = XmlHelper::canonicalize($node);
        }
        // When there is no reference, the digest is over the entire XML.
        // If the XML already has a "Signature" node within the root node, it
        // must be removed before obtaining its C14N.
        else {
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
            $dataToDigest = $docClone->C14N();
        }

        // Calculate the digest over the XML data in C14N format.
        $digestValue = base64_encode(sha1($dataToDigest, true));

        // Return the calculated digest.
        return $digestValue;
    }

    /**
     * Sign the `SignedInfo` node of the XML document using a digital
     * certificate. If a certificate was not previously provided, it can be
     * passed as an argument in the signature.
     *
     * @param SignatureInterface $signatureNode The signature node that will be signed.
     * @param CertificateInterface $certificate Digital certificate to use for signing.
     * @param string $xmlTemplate XML of the document with the `<Signature/>`
     * placeholder where the signature node will be placed. The `SignedInfo` is
     * canonicalized as it will be in that document, with the namespaces that
     * it inherits, which is how it is verified.
     * @return SignatureInterface The signed signature node.
     * @throws LogicException If the conditions to sign are not met.
     */
    private function signSignature(
        SignatureInterface $signatureNode,
        CertificateInterface $certificate,
        string $xmlTemplate
    ): SignatureInterface {
        // Validate that the digital certificate is assigned.
        if ($signatureNode->getX509Certificate() === null) {
            throw new LogicException(
                'It is not possible to generate the signature of the Signature node if the digital certificate is not assigned.'
            );
        }

        // Create the XML document of the electronic signature node.
        $nodeXml = $this->createSignatureNodeXml(
            $signatureNode
        );

        // Generate the string XML of the data that will be signed.
        // SignedInfo is always present because $nodeXml is freshly built from
        // the Signature::$data template, which always declares it.
        // The signature node is placed in the XML as it will be in the signed
        // document, so the C14N of `SignedInfo` has the namespaces that it
        // inherits from the elements that contain it. It is done with the text
        // of the XML, as the final document is built, since importing the
        // nodes could change the prefixes of its elements. The new signature is
        // the last one, the document could have others.
        $contextDoc = new XmlDocument();
        $contextDoc->loadXml(
            str_replace('<Signature/>', $nodeXml->getXml(), $xmlTemplate)
        );
        $signedInfoNode = $contextDoc->getNodes(
            "(/*/*[local-name()='Signature'])[last()]/*[local-name()='SignedInfo']"
        )->item(0);
        $signedInfoNode instanceof DOMNode || throw new LogicException('SignedInfo node is missing from the generated Signature XML.');
        $signedInfoC14N = XmlHelper::canonicalize($signedInfoNode);

        // Generate the signature of the data, the tag `SignedInfo`.
        $signature = $this->sign(
            $signedInfoC14N,
            $certificate->getPrivateKey()
        );

        // Assign the calculated signature to the signature node.
        $signatureNode->setSignatureValue($signature);

        // Regenerate the XML of the signature node after assigning the
        // SignatureValue (setSignatureValue() invalidates the previous XML).
        $this->createSignatureNodeXml($signatureNode);

        // Return the signature node.
        return $signatureNode;
    }

    /**
     * Creates the Xml instance of Signature and assigns it to this.
     *
     * @param SignatureInterface $signatureNode
     * @return XmlDocumentInterface
     */
    private function createSignatureNodeXml(
        SignatureInterface $signatureNode
    ): XmlDocumentInterface {
        $xml = $this->xmlService->encode($signatureNode->getData());
        $xml->setFormatOutput(false);
        $signatureNode->setXml($xml);

        return $signatureNode->getXml();
    }
}
