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
use Derafu\Signature\Contract\SignatureGeneratorInterface;
use Derafu\Signature\Contract\SignatureInterface;
use Derafu\Signature\Contract\SignatureValidatorInterface;
use Derafu\Signature\Exception\SignatureException;
use Derafu\Signature\Signature;
use Derafu\Xml\Contract\XmlDocumentInterface;
use Derafu\Xml\Contract\XmlServiceInterface;
use Derafu\Xml\XmlDocument;

/**
 * Class that handles the validation of electronic signatures.
 */
final class SignatureValidator implements SignatureValidatorInterface
{
    public function __construct(
        private readonly SignatureGeneratorInterface $generator,
        private readonly XmlServiceInterface $xmlService
    ) {
    }

    /**
     * {@inheritDoc}
     */
    public function validate(
        string $data,
        string $signature,
        string $publicKey,
        string|int $signatureAlgorithm = OPENSSL_ALGO_SHA1
    ): bool {
        $publicKey = AsymmetricKeyHelper::normalizePublicKey($publicKey);

        $result = openssl_verify(
            $data,
            base64_decode($signature),
            $publicKey,
            $signatureAlgorithm
        );

        if ($result === -1) {
            throw new SignatureException(
                'An error occurred while verifying the electronic signature of the data.'
            );
        }

        return $result === 1;
    }

    /**
     * {@inheritDoc}
     */
    public function validateXml(XmlDocumentInterface|string $xml): void
    {
        // If an Xml object is passed, it is converted to a string.
        if (!is_string($xml)) {
            $xml = $xml->saveXml();
        }

        // Load the string XML into an XML document.
        $doc = new XmlDocument();
        $doc->loadXml($xml);
        if (!$doc->documentElement) {
            throw new SignatureException(
                'Could not get the documentElement from the XML to validate its signature (possible malformed XML).'
            );
        }

        // Search for all elements that are tag Signature.
        // An XML document can have more than one signature.
        $signaturesElements = $doc->documentElement->getElementsByTagName(
            'Signature'
        );

        // If no signatures are found in the XML, an error is thrown.
        if (!$signaturesElements->length) {
            throw new SignatureException(
                'No signatures were found in the XML to validate.'
            );
        }

        // Iterate each signature found.
        foreach ($signaturesElements as $signatureElement) {
            // Build the signature node instance.
            $signatureNode = $this->createSignatureNode(
                $signatureElement->C14N()
            );

            // Validate the electronic signature node.
            $this->validateXmlDigestValue($doc, $signatureNode);
            $this->validateXmlSignatureValue($signatureNode);
        }
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
        // If an Xml object is passed, it is converted to a string.
        if (!is_string($xml)) {
            $xml = $xml->saveXml();
        }

        // Load the string XML into an XML document.
        $doc = new XmlDocument();
        $doc->loadXml($xml);
        if (!$doc->documentElement) {
            throw new SignatureException(
                'Could not get the documentElement from the XML to validate its signature (possible malformed XML).'
            );
        }

        // Get the digest value that comes in the XML (in the signature node).
        $digestValueXml = $signatureNode->getDigestValue();
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
            throw new SignatureException(sprintf(
                'The DigestValue that comes in the XML "%s" for the reference "%s" does not match the calculated value when validating "%s". The data of the reference could have been manipulated after being signed.',
                $digestValueXml,
                $reference,
                $digestValueCalculated
            ));
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
        $xpath = '//*[@ID="' . ltrim($reference, '#') . '"]';
        $node = $doc->getNodes($xpath)->item(0);
        if ($node === null) {
            return null;
        }

        // Try exclusive C14N (only includes visibly-utilized namespaces).
        $hash = base64_encode(sha1($node->C14N(true, false), true));
        if ($hash === $expected) {
            return $hash;
        }

        // Try strip-inherited-namespaces + standard C14N: serialize the node,
        // remove all xmlns declarations (inherited from ancestors), re-parse, C14N.
        // This matches how LibreDTE and the SII's official example DTE are signed.
        $newDoc = new XmlDocument();
        $newDoc->appendChild($newDoc->importNode($node, true));
        $serialized = $newDoc->saveXml($newDoc->documentElement);
        $stripped = (string) preg_replace('/ xmlns(?::[^=]*)?\s*=\s*"[^"]*"/', '', $serialized);
        $stripped = '<?xml version="1.0" encoding="UTF-8"?>' . $stripped;
        $strippedDoc = new XmlDocument();
        if (@$strippedDoc->loadXml($stripped) && $strippedDoc->documentElement) {
            $hash = base64_encode(sha1($strippedDoc->documentElement->C14N(false, false), true));
            if ($hash === $expected) {
                return $hash;
            }
        }

        return null;
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
        $signedInfoC14N = $signedInfoNode !== null
            ? $signedInfoNode->C14N(false, false)
            : $signatureNode->getXml()->C14NEncoded($xpath);

        // Validate the electronic signature.
        $isValid = $this->validate($signedInfoC14N, $signatureValue, $x509Certificate);

        // If standard C14N fails, try exclusive C14N as fallback.
        if (!$isValid && $signedInfoNode !== null) {
            $signedInfoC14N = $signedInfoNode->C14N(true, false);
            $isValid = $this->validate($signedInfoC14N, $signatureValue, $x509Certificate);
        }

        // If the electronic signature is not valid, an exception is thrown.
        if (!$isValid) {
            throw new SignatureException(sprintf(
                'The electronic signature of the `SignedInfo` node of the XML for the reference "%s" is not valid.',
                $signatureNode->getReference()
            ));
        }
    }
}
