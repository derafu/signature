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

use Derafu\Certificate\Contract\CertificateInterface;
use Derafu\Certificate\Service\CertificateFaker;
use Derafu\Certificate\Service\CertificateLoader;
use Derafu\Signature\Service\SignatureGenerator;
use Derafu\Signature\Service\SignatureService;
use Derafu\Signature\Service\SignatureValidator;
use Derafu\Xml\Service\XmlDecoder;
use Derafu\Xml\Service\XmlEncoder;
use Derafu\Xml\Service\XmlService;
use Derafu\Xml\Service\XmlValidator;

/**
 * Signs and verifies documents with `xmlsec1`, an implementation of XML
 * Signature that is not this library, and gives the service of the library to
 * compare them.
 *
 * The tests that use `xmlsec1` call `requireXmlsec()`, that skips them if the
 * command is not installed.
 */
trait UsesXmlsec
{
    protected const DSIG = 'http://www.w3.org/2000/09/xmldsig#';

    protected const C14N = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';

    protected const EXC_C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#';

    protected const ENVELOPED = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';

    protected const XPATH = 'http://www.w3.org/TR/1999/REC-xpath-19991116';

    protected const DIGESTS = [
        'sha1' => 'http://www.w3.org/2000/09/xmldsig#sha1',
        'sha256' => 'http://www.w3.org/2001/04/xmlenc#sha256',
        'sha384' => 'http://www.w3.org/2001/04/xmldsig-more#sha384',
        'sha512' => 'http://www.w3.org/2001/04/xmlenc#sha512',
    ];

    protected const SIGNATURES = [
        'sha1' => 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
        'sha256' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
        'sha384' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384',
        'sha512' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512',
    ];

    private SignatureService $service;

    private CertificateInterface $certificate;

    private ?string $xmlsecDirectory = null;

    /**
     * Creates the service of the library and a certificate to sign.
     */
    private function createService(): void
    {
        $xmlService = new XmlService(
            new XmlEncoder(),
            new XmlDecoder(),
            new XmlValidator()
        );
        $generator = new SignatureGenerator($xmlService);
        $this->service = new SignatureService(
            new RecordingSignatureGenerator($generator),
            new RecordingSignatureValidator(new SignatureValidator($generator, $xmlService))
        );
        $this->certificate = (new CertificateFaker(new CertificateLoader()))
            ->createFake()
        ;
    }

    /**
     * Skips the test if `xmlsec1` is not installed. If it is, it creates the
     * service and the directory with the key and the certificate for `xmlsec1`.
     */
    private function requireXmlsec(): void
    {
        exec('command -v xmlsec1', $output, $status);
        if ($status !== 0) {
            $this->markTestSkipped('The xmlsec1 command is not installed.');
        }

        $this->createService();
        $this->xmlsecDirectory = sys_get_temp_dir() . '/derafu-signature-xmlsec-' . bin2hex(random_bytes(6));
        mkdir($this->xmlsecDirectory);
        file_put_contents($this->xmlsecDirectory . '/key.pem', $this->certificate->getPrivateKey());
        file_put_contents($this->xmlsecDirectory . '/cert.pem', $this->certificate->getCertificate());
    }

    protected function tearDown(): void
    {
        // Without `xmlsec1` the test is skipped before the directory exists.
        if ($this->xmlsecDirectory === null) {
            return;
        }

        foreach (glob($this->xmlsecDirectory . '/*') ?: [] as $file) {
            unlink($file);
        }
        rmdir($this->xmlsecDirectory);
        $this->xmlsecDirectory = null;
    }

    /**
     * Builds the template of a `Signature` for `xmlsec1`.
     *
     * @param list<array{string, string, list<array{string, string}>}> $references
     * For each reference: URI, digest algorithm and transforms (algorithm and
     * content).
     * @param bool $keyValue Whether the `KeyInfo` has a `KeyValue`, as the
     * signatures of this library.
     * @param string $object Content of an `Object` of the signature.
     */
    private function template(
        string $prefix,
        string $signatureMethod,
        string $canonicalization,
        array $references,
        bool $keyValue = false,
        string $object = ''
    ): string {
        $namespace = $prefix === '' ? ' xmlns="' . self::DSIG . '"' : ' xmlns:' . $prefix . '="' . self::DSIG . '"';
        $q = $prefix === '' ? '' : $prefix . ':';

        $xml = '';
        foreach ($references as [$uri, $digestMethod, $transforms]) {
            $items = '';
            foreach ($transforms as [$algorithm, $content]) {
                $items .= '<' . $q . 'Transform Algorithm="' . $algorithm . '">'
                    . ($algorithm === self::XPATH ? '<' . $q . 'XPath>' . $content . '</' . $q . 'XPath>' : $content)
                    . '</' . $q . 'Transform>';
            }
            $xml .= '<' . $q . 'Reference URI="' . $uri . '">'
                . ($items !== '' ? '<' . $q . 'Transforms>' . $items . '</' . $q . 'Transforms>' : '')
                . '<' . $q . 'DigestMethod Algorithm="' . $digestMethod . '"/><' . $q . 'DigestValue/></' . $q . 'Reference>';
        }

        return '<' . $q . 'Signature' . $namespace . '><' . $q . 'SignedInfo>'
            . '<' . $q . 'CanonicalizationMethod Algorithm="' . $canonicalization . '"/>'
            . '<' . $q . 'SignatureMethod Algorithm="' . $signatureMethod . '"/>'
            . $xml
            . '</' . $q . 'SignedInfo><' . $q . 'SignatureValue/>'
            . '<' . $q . 'KeyInfo><' . $q . 'KeyName>key</' . $q . 'KeyName>'
            . ($keyValue ? '<' . $q . 'KeyValue/>' : '')
            . '<' . $q . 'X509Data/></' . $q . 'KeyInfo>'
            . $object
            . '</' . $q . 'Signature>';
    }

    /**
     * Signs a document with `xmlsec1`.
     *
     * @param string $xml Document with the template of the signature.
     * @param string $ids Elements and attributes that identify them, as
     * `ID Doc` (attribute `ID` of the elements `Doc`), separated by `;`.
     * @param string|null $nodeXPath XPath of the signature to sign, if it is
     * not the first one of the document.
     */
    private function signWithXmlsec(string $xml, string $ids = 'ID Doc', ?string $nodeXPath = null): string
    {
        $input = $this->xmlsecDirectory . '/input.xml';
        $output = $this->xmlsecDirectory . '/output.xml';
        file_put_contents($input, $xml);
        if (file_exists($output)) {
            unlink($output);
        }

        $command = 'xmlsec1 --sign --privkey-pem:key '
            . escapeshellarg($this->xmlsecDirectory . '/key.pem') . ',' . escapeshellarg($this->xmlsecDirectory . '/cert.pem')
            . $this->xmlsecOptions($ids, $nodeXPath)
            . ' --output ' . escapeshellarg($output) . ' ' . escapeshellarg($input) . ' 2>&1';
        exec($command, $lines, $status);
        $this->assertSame(0, $status, implode("\n", $lines));

        $signed = file_get_contents($output);
        $this->assertIsString($signed);
        // The signature that is made is the last one of the document.
        $values = SignatureShape::signatureValues($signed);
        SignedDocumentsLog::record(
            SignedDocumentsLog::SIGNED_BY_XMLSEC,
            $signed,
            $values !== [] ? $values[array_key_last($values)] : null
        );

        return $signed;
    }

    /**
     * Verifies a signed document with `xmlsec1`, without validating the chain
     * of the certificate (the one of the tests is not issued by an authority).
     *
     * @param string $ids Elements and attributes that identify them, see
     * `signWithXmlsec()`.
     * @param int|null $signature Number of the signature to verify (the first
     * is 1), if it is not the first one of the document.
     * @return bool `true` if `xmlsec1` verifies the signature.
     */
    private function verifyWithXmlsec(string $signed, string $ids = 'ID Doc', ?int $signature = null): bool
    {
        $file = $this->xmlsecDirectory . '/signed.xml';
        file_put_contents($file, $signed);

        $node = $signature !== null ? "(//*[local-name()='Signature'])[" . $signature . ']' : null;
        exec(
            'xmlsec1 --verify --insecure' . $this->xmlsecOptions($ids, $node) . ' ' . escapeshellarg($file) . ' 2>&1',
            $lines,
            $status
        );

        $verified = $status === 0 && str_contains(implode("\n", $lines), 'Verification status: OK');
        if ($verified) {
            SignedDocumentsLog::record(
                SignedDocumentsLog::VERIFIED_BY_XMLSEC,
                $signed,
                SignatureShape::signatureValues($signed)[($signature ?? 1) - 1] ?? null
            );
        }

        return $verified;
    }

    /**
     * Gives the options of `xmlsec1` for the identifiers and the signature.
     */
    private function xmlsecOptions(string $ids, ?string $nodeXPath): string
    {
        $options = '';
        foreach (explode(';', $ids) as $id) {
            $options .= ' --id-attr:' . $id;
        }

        return $options . ($nodeXPath !== null ? ' --node-xpath ' . escapeshellarg($nodeXPath) : '');
    }
}
