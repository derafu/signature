<?php

declare(strict_types=1);

/**
 * Derafu: Signature - Library for digital signatures.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsSignature;

use Derafu\Signature\Exception\SignatureException;
use Derafu\Signature\Service\SignatureGenerator;
use Derafu\Signature\Service\SignatureService;
use Derafu\Signature\Service\SignatureValidator;
use Derafu\Signature\Signature;
use Derafu\Signature\SignatureValidationResult;
use Derafu\Signature\Support\Algorithms;
use Derafu\Signature\Support\RawSignature;
use Derafu\Signature\Support\ReferenceData;
use Derafu\Signature\Support\ReferenceTarget;
use Derafu\Signature\Support\SignatureElements;
use Derafu\Signature\Support\SignatureOptions;
use Derafu\Signature\Translation\SignatureTranslationResourceProvider;
use Derafu\TestsSignature\Support\CreatesKeys;
use Derafu\TestsSignature\Support\ReadsData;
use Derafu\TestsSignature\Support\UsesXmlsec;
use Derafu\Xml\XmlDocument;
use Derafu\Xml\XmlError;
use Derafu\Xml\XmlErrorLevel;
use DOMDocument;
use DOMElement;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Details of how the service signs and validates: what it does not take for the
 * signature that it makes, what it leaves in libxml, the size of what it signs
 * with the curves, and what its errors say.
 */
#[CoversClass(Signature::class)]
#[CoversClass(SignatureService::class)]
#[CoversClass(SignatureGenerator::class)]
#[CoversClass(SignatureValidator::class)]
#[CoversClass(SignatureValidationResult::class)]
#[CoversClass(SignatureException::class)]
#[CoversClass(SignatureTranslationResourceProvider::class)]
#[CoversClass(Algorithms::class)]
#[CoversClass(RawSignature::class)]
#[CoversClass(ReferenceData::class)]
#[CoversClass(ReferenceTarget::class)]
#[CoversClass(SignatureElements::class)]
#[CoversClass(SignatureOptions::class)]
final class SignatureServiceDetailsTest extends TestCase
{
    use ReadsData;

    use CreatesKeys;
    use UsesXmlsec;

    protected function setUp(): void
    {
        $this->createService();
    }

    private function countSignatures(string $xml): int
    {
        return (int) preg_match_all('~<Signature[ >]~', $xml);
    }

    public function testAnElementWithTheNameOfThePlaceholderIsKept(): void
    {
        $signed = $this->service->signXml('<r><DerafuSignature/><a/></r>', $this->certificate);

        $this->assertSame(1, substr_count($signed, '<DerafuSignature/>'));
        $this->assertSame(1, $this->countSignatures($signed));
        $this->assertTrue($this->service->validateXml($signed)[0]->isValid());
    }

    public function testAnObjectWithTheNameOfThePlaceholderIsKeptInADetachedSignature(): void
    {
        $signed = $this->service->signXmlDetached($this->certificate, [
            'references' => [['uri' => '#o1']],
            'objects' => [['xml' => '<DerafuSignature/>', 'id' => 'o1']],
        ]);

        $this->assertSame(1, substr_count($signed, '<DerafuSignature/>'));
        $this->assertTrue($this->service->validateXml($signed)[0]->isValid());
    }

    public function testAReferenceThatIsWrittenWithTheHashIsTheSameIdWithOneHash(): void
    {
        $signed = $this->service->signXml('<Root><Doc ID="A"/></Root>', $this->certificate, ['reference' => '#A']);

        $this->assertStringContainsString('URI="#A"', $signed);
        $this->assertStringNotContainsString('##A', $signed);
        $this->assertTrue($this->service->validateXml($signed)[0]->isValid());
    }

    public function testManyObjectsAreAllInTheSignatureWithTheirOwnContent(): void
    {
        $objects = [];
        for ($i = 0; $i < 12; $i++) {
            $objects[] = ['xml' => '<o n="' . $i . '"/>', 'id' => 'o' . $i];
        }

        $signed = $this->service->signXml('<Root><Doc ID="A"/></Root>', $this->certificate, ['objects' => $objects]);

        for ($i = 0; $i < 12; $i++) {
            $this->assertSame(1, substr_count($signed, '<Object Id="o' . $i . '"><o n="' . $i . '"/></Object>'), 'Object ' . $i);
        }
        $this->assertTrue($this->service->validateXml($signed)[0]->isValid());
    }

    /**
     * @return array<string, array{string, string, int}>
     */
    public static function curveProvider(): array
    {
        return [
            'P-256' => ['prime256v1', 'ecdsa-sha256', 64],
            'P-384' => ['secp384r1', 'ecdsa-sha384', 96],
        ];
    }

    #[DataProvider('curveProvider')]
    public function testTheSignatureOfACurveHasTwoIntegersOfTheSizeOfItsOrder(string $curve, string $algorithm, int $size): void
    {
        $certificate = $this->createCertificate(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => $curve]);

        $signed = $this->service->signXml('<Root><Doc ID="A"/></Root>', $certificate, ['signature_algorithm' => $algorithm]);

        $this->assertSame(1, preg_match('~<SignatureValue>([^<]+)</SignatureValue>~', $signed, $matches));
        $this->assertSame($size, strlen((string) base64_decode((string) preg_replace('/\s+/', '', $matches[1] ?? ''), true)));
        $this->assertTrue($this->service->validateXml($signed)[0]->isValid());
    }

    /**
     * @return array<string, array{array<string, mixed>}>
     */
    public static function locationProvider(): array
    {
        return [
            'an XPath that is valid' => [['xpath' => '/r/a']],
            'an XPath that is not valid' => [['xpath' => '/r/']],
        ];
    }

    /**
     * @param array<string, mixed> $location
     */
    #[DataProvider('locationProvider')]
    public function testTheLocationLeavesLibxmlAsItWas(array $location): void
    {
        foreach ([true, false] as $internalErrors) {
            $before = libxml_use_internal_errors($internalErrors);
            libxml_clear_errors();

            try {
                try {
                    $this->service->signXml('<r><a/></r>', $this->certificate, ['signature_location' => $location]);
                } catch (SignatureException) {
                    // The XPath that is not valid is an error of the signature.
                }
                $this->assertSame([], libxml_get_errors());
                $this->assertSame($internalErrors, libxml_use_internal_errors($internalErrors));
            } finally {
                libxml_clear_errors();
                libxml_use_internal_errors($before);
            }
        }
    }

    public function testTheErrorOfADigestThatDoesNotMatchSaysTheReferenceAndTheValueCalculated(): void
    {
        $signed = $this->service->signXml(
            '<Root xmlns:u="urn:u"><Doc ID="A"/></Root>',
            $this->certificate,
            ['reference' => 'A', 'digest_algorithm' => 'sha256']
        );
        $this->assertSame(1, preg_match('~<DigestValue>([^<]+)</DigestValue>~', $signed, $matches));
        $digest = $matches[1] ?? '';
        $tampered = base64_encode(str_repeat("\x00", 32));

        $result = $this->service->validateXml(str_replace($digest, $tampered, $signed))[0];

        $this->assertFalse($result->isValid());
        $this->assertSame(
            'The DigestValue that comes in the XML "' . $tampered . '" for the reference "#A" does not match the calculated value when validating "' . $digest . '". The data of the reference could have been manipulated after being signed.',
            $result->getError()?->getMessage()
        );
    }

    /**
     * The signature that is reported when none is valid is the one as it is in
     * the document, with the namespaces that are in scope there.
     */
    public function testTheSignatureThatIsReportedAsInvalidIsTheOneAsItIsInTheDocument(): void
    {
        $signed = $this->service->signXml(
            '<r xmlns:u="urn:u"><w xmlns:v="urn:v"><a>1</a></w></r>',
            $this->certificate,
            ['signature_location' => ['xpath' => '/r/w']]
        );

        $result = $this->service->validateXml(str_replace('<a>1</a>', '<a>2</a>', $signed))[0];

        $this->assertFalse($result->isValid());
        $data = $result->getSignatureNode()->getData();
        $this->assertSame('urn:u', $this->at($data, 'Signature', '@attributes', 'xmlns:u'));
        $this->assertSame('urn:v', $this->at($data, 'Signature', '@attributes', 'xmlns:v'));
    }

    public function testTheErrorsOfTheResultAreTexts(): void
    {
        $error = new SignatureException(
            'The signature is not valid.',
            errors: [new XmlError(XmlErrorLevel::Fatal, 76, 3, 14, "Opening and ending tag mismatch\n")]
        );

        $array = (new SignatureValidationResult(new Signature(), $error))->toArray();

        $this->assertSame(['Line 3, column 14: Opening and ending tag mismatch'], $array['error']['errors'] ?? null);
    }

    /**
     * Signs again the `SignedInfo` of a signature that was changed by hand, as
     * another system that canonicalizes in another way would have signed it.
     */
    private function signAgain(string $signed): string
    {
        $doc = new DOMDocument();
        $doc->loadXML($signed);
        $signedInfo = $doc->getElementsByTagNameNS(self::DSIG, 'SignedInfo')->item(0);
        $value = $doc->getElementsByTagNameNS(self::DSIG, 'SignatureValue')->item(0);
        $this->assertInstanceOf(DOMElement::class, $signedInfo);
        $this->assertInstanceOf(DOMElement::class, $value);

        $signature = '';
        $this->assertTrue(openssl_sign($signedInfo->C14N(), $signature, $this->certificate->getPrivateKey(), OPENSSL_ALGO_SHA1));
        $this->assertIsString($signature);
        $value->textContent = base64_encode($signature);

        return (string) $doc->saveXML();
    }

    /**
     * An element that was signed with the exclusive canonicalization is valid
     * even if its reference says that it was the inclusive one: other systems
     * sign it like that.
     */
    public function testAnElementSignedWithTheExclusiveCanonicalizationIsValidEvenIfTheReferenceSaysAnother(): void
    {
        $signed = $this->service->signXml(
            '<Root xmlns:u="urn:u" xmlns:v="urn:v"><u:Doc ID="A"/></Root>',
            $this->certificate,
            ['references' => [['uri' => '#A', 'transforms' => ['exc_c14n']]]]
        );
        $this->assertTrue($this->service->validateXml($signed)[0]->isValid());

        $changed = str_replace(self::EXC_C14N, self::C14N, $signed);
        $this->assertNotSame($signed, $changed);

        $this->assertFalse($this->service->validateXml($changed)[0]->isValid());
        $this->assertTrue($this->service->validateXml($this->signAgain($changed))[0]->isValid());
    }

    /**
     * A signature made in a document that was embedded later in a bigger one is
     * valid: the namespaces of the new ancestors were not there when it was made,
     * and the canonicalization is tried as if the document began in each
     * ancestor.
     */
    public function testASignatureMadeInADocumentThatWasEmbeddedLaterIsValid(): void
    {
        $signed = $this->service->signXml(
            '<env xmlns:e="urn:e"><mid xmlns:m="urn:m"><el Id="x"/></mid></env>',
            $this->certificate,
            ['reference' => 'x', 'signature_location' => ['xpath' => '//mid']]
        );
        $this->assertTrue($this->service->validateXml($signed)[0]->isValid());

        $embedded = '<root xmlns:r="urn:r">' . (string) preg_replace('/^<\?xml[^>]*\?>\s*/', '', $signed) . '</root>';

        $this->assertTrue($this->service->validateXml($embedded)[0]->isValid());
    }

    /**
     * Calculating the digest of a document does not change it: the signature
     * that it has is left out of the digest, not removed from the document.
     */
    public function testTheDigestOfADocumentThatHasASignatureDoesNotChangeTheDocument(): void
    {
        $xml = '<r><a/><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><x/></Signature></r>';
        $doc = new XmlDocument();
        $doc->loadXml($xml);
        $before = $doc->saveXml();

        $digest = $this->service->generateXmlDigestValue($doc);

        $this->assertSame($before, $doc->saveXml());
        $without = new XmlDocument();
        $without->loadXml('<r><a/></r>');
        $this->assertSame($this->service->generateXmlDigestValue($without), $digest);
    }
}
