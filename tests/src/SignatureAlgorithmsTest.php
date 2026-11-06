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
use Derafu\TestsSignature\Support\ReadsXml;
use Derafu\TestsSignature\Support\UsesXmlsec;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The algorithms of the digest and of the signature: the ones that are signed
 * with the library are validated with the library and with `xmlsec1`, and the
 * ones that `xmlsec1` signs are validated with the library.
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
final class SignatureAlgorithmsTest extends TestCase
{
    use CreatesKeys;
    use ReadsXml;
    use UsesXmlsec;

    private const XML = "<Root>\n  <Doc ID=\"A\">\n    <V>1</V>\n  </Doc>\n</Root>\n";

    private const SIGNATURE_URIS = [
        'rsa-sha1' => 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
        'rsa-sha224' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha224',
        'rsa-sha256' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
        'rsa-sha384' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384',
        'rsa-sha512' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512',
        'ecdsa-sha1' => 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1',
        'ecdsa-sha224' => 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha224',
        'ecdsa-sha256' => 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256',
        'ecdsa-sha384' => 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384',
        'ecdsa-sha512' => 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512',
        'dsa-sha1' => 'http://www.w3.org/2000/09/xmldsig#dsa-sha1',
        'dsa-sha256' => 'http://www.w3.org/2009/xmldsig11#dsa-sha256',
    ];

    private const DIGEST_URIS = [
        'sha1' => 'http://www.w3.org/2000/09/xmldsig#sha1',
        'sha224' => 'http://www.w3.org/2001/04/xmldsig-more#sha224',
        'sha256' => 'http://www.w3.org/2001/04/xmlenc#sha256',
        'sha384' => 'http://www.w3.org/2001/04/xmldsig-more#sha384',
        'sha512' => 'http://www.w3.org/2001/04/xmlenc#sha512',
    ];

    protected function setUp(): void
    {
        $this->requireXmlsec();
    }

    /**
     * Gives the value of an attribute of the first element that an XPath finds.
     */
    private function attribute(string $signed, string $query, string $attribute): string
    {
        return $this->firstElement($signed, $query)->getAttribute($attribute);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function digestProvider(): array
    {
        $cases = [];
        foreach (array_keys(self::DIGEST_URIS) as $digest) {
            $cases[$digest] = [$digest];
        }

        return $cases;
    }

    #[DataProvider('digestProvider')]
    public function testEveryDigestAlgorithmIsSignedAndValidatedByTheLibraryAndByXmlsec(string $digest): void
    {
        $signed = $this->service->signXml(self::XML, $this->certificate, [
            'reference' => 'A',
            'digest_algorithm' => $digest,
        ]);

        $this->assertSame(
            self::DIGEST_URIS[$digest],
            $this->attribute($signed, '//*[local-name()="DigestMethod"]', 'Algorithm')
        );
        $results = $this->service->validateXml($signed);
        $this->assertCount(1, $results);
        $this->assertTrue($results[0]->isValid(), (string) $results[0]->getError()?->getMessage());
        $this->assertTrue($this->verifyWithXmlsec($signed));
    }

    #[DataProvider('digestProvider')]
    public function testEveryDigestAlgorithmThatXmlsecSignsIsValidatedByTheLibrary(string $digest): void
    {
        $template = '<Root><Doc ID="A"><V>1</V></Doc>'
            . $this->template('', self::SIGNATURES['sha256'], self::C14N, [
                ['#A', self::DIGESTS['sha256'], [[self::C14N, '']]],
            ])
            . '</Root>';
        $template = str_replace(self::DIGESTS['sha256'], self::DIGEST_URIS[$digest], $template);

        $signed = $this->signWithXmlsec($template);

        $results = $this->service->validateXml($signed);
        $this->assertTrue($results[0]->isValid(), (string) $results[0]->getError()?->getMessage());
    }

    #[DataProvider('digestProvider')]
    public function testTamperedDataOfEveryDigestAlgorithmIsNotValid(string $digest): void
    {
        $signed = $this->service->signXml(self::XML, $this->certificate, [
            'reference' => 'A',
            'digest_algorithm' => $digest,
        ]);

        $results = $this->service->validateXml(str_replace('<V>1</V>', '<V>2</V>', $signed));

        $this->assertFalse($results[0]->isValid());
    }

    /**
     * @return array<string, array{string}>
     */
    public static function rsaProvider(): array
    {
        $cases = [];
        foreach (['rsa-sha1', 'rsa-sha224', 'rsa-sha256', 'rsa-sha384', 'rsa-sha512'] as $algorithm) {
            $cases[$algorithm] = [$algorithm];
        }

        return $cases;
    }

    #[DataProvider('rsaProvider')]
    public function testEveryRsaAlgorithmIsSignedAndValidatedByTheLibraryAndByXmlsec(string $algorithm): void
    {
        $signed = $this->service->signXml(self::XML, $this->certificate, [
            'reference' => 'A',
            'signature_algorithm' => $algorithm,
            'digest_algorithm' => 'sha256',
        ]);

        $this->assertSame(
            self::SIGNATURE_URIS[$algorithm],
            $this->attribute($signed, '//*[local-name()="SignatureMethod"]', 'Algorithm')
        );
        $results = $this->service->validateXml($signed);
        $this->assertTrue($results[0]->isValid(), (string) $results[0]->getError()?->getMessage());
        $this->assertTrue($this->verifyWithXmlsec($signed));
    }

    #[DataProvider('rsaProvider')]
    public function testEveryRsaAlgorithmThatXmlsecSignsIsValidatedByTheLibrary(string $algorithm): void
    {
        $template = '<Root><Doc ID="A"><V>1</V></Doc>'
            . $this->template('', self::SIGNATURE_URIS[$algorithm], self::C14N, [
                ['#A', self::DIGESTS['sha256'], [[self::C14N, '']]],
            ])
            . '</Root>';

        $signed = $this->signWithXmlsec($template);

        $results = $this->service->validateXml($signed);
        $this->assertTrue($results[0]->isValid(), (string) $results[0]->getError()?->getMessage());
    }

    /**
     * @return array<string, array{string, array<string, mixed>}>
     */
    public static function ellipticCurveProvider(): array
    {
        return [
            'P-256 with sha256' => ['ecdsa-sha256', ['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']],
            'P-256 with sha1' => ['ecdsa-sha1', ['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']],
            'P-256 with sha224' => ['ecdsa-sha224', ['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']],
            'P-384 with sha384' => ['ecdsa-sha384', ['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'secp384r1']],
            'P-521 with sha512' => ['ecdsa-sha512', ['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'secp521r1']],
        ];
    }

    /**
     * @param array<string, mixed> $key
     */
    #[DataProvider('ellipticCurveProvider')]
    public function testEcdsaIsSignedAndValidatedByTheLibraryAndByXmlsec(string $algorithm, array $key): void
    {
        $this->useCertificate($this->createCertificate($key));

        $signed = $this->service->signXml(self::XML, $this->certificate, [
            'reference' => 'A',
            'signature_algorithm' => $algorithm,
            'digest_algorithm' => 'sha256',
        ]);

        // The key is in the certificate: the elliptic curves have no `KeyValue`.
        $this->assertStringNotContainsString('KeyValue', $signed);
        $this->assertStringContainsString('X509Certificate', $signed);
        $results = $this->service->validateXml($signed);
        $this->assertTrue($results[0]->isValid(), (string) $results[0]->getError()?->getMessage());
        $this->assertTrue($this->verifyWithXmlsec($signed));
    }

    /**
     * @param array<string, mixed> $key
     */
    #[DataProvider('ellipticCurveProvider')]
    public function testEcdsaThatXmlsecSignsIsValidatedByTheLibrary(string $algorithm, array $key): void
    {
        $this->useCertificate($this->createCertificate($key));
        $template = '<Root><Doc ID="A"><V>1</V></Doc>'
            . $this->template('', self::SIGNATURE_URIS[$algorithm], self::C14N, [
                ['#A', self::DIGESTS['sha256'], [[self::C14N, '']]],
            ])
            . '</Root>';

        $signed = $this->signWithXmlsec($template);

        $results = $this->service->validateXml($signed);
        $this->assertTrue($results[0]->isValid(), (string) $results[0]->getError()?->getMessage());
    }

    /**
     * The integers of a signature of P-521 have 65 or 66 bytes, depending on the
     * value (it is not a multiple of 8 bits): all of them are written with the
     * size of the order of the curve.
     */
    public function testEverySignatureOfP521HasTheSizeOfTheOrderOfTheCurve(): void
    {
        $this->useCertificate($this->createCertificate(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'secp521r1']));

        for ($i = 0; $i < 12; $i++) {
            $signed = $this->service->signXml('<Root><Doc ID="A"><V>' . $i . '</V></Doc></Root>', $this->certificate, [
                'reference' => 'A',
                'signature_algorithm' => 'ecdsa-sha512',
            ]);

            $value = (string) preg_replace('#^.*<SignatureValue>(.*?)</SignatureValue>.*$#s', '$1', $signed);
            $this->assertSame(132, strlen((string) base64_decode($value)));
            $results = $this->service->validateXml($signed);
            $this->assertTrue($results[0]->isValid(), (string) $results[0]->getError()?->getMessage());
        }
    }

    public function testTamperedDataOfEcdsaIsNotValid(): void
    {
        $this->useCertificate($this->createCertificate(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']));
        $signed = $this->service->signXml(self::XML, $this->certificate, [
            'reference' => 'A',
            'signature_algorithm' => 'ecdsa-sha256',
        ]);

        $results = $this->service->validateXml(str_replace('<V>1</V>', '<V>2</V>', $signed));

        $this->assertFalse($results[0]->isValid());
    }

    public function testASignatureValueOfEcdsaThatIsNotTwoIntegersIsNotValid(): void
    {
        $this->useCertificate($this->createCertificate(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']));
        $signed = $this->service->signXml(self::XML, $this->certificate, [
            'reference' => 'A',
            'signature_algorithm' => 'ecdsa-sha256',
        ]);
        $broken = (string) preg_replace(
            '#(<SignatureValue>)[^<]*(</SignatureValue>)#',
            '$1' . base64_encode('odd') . '$2',
            $signed
        );

        $results = $this->service->validateXml($broken);

        $this->assertFalse($results[0]->isValid());
    }

    public function testDsaWithSha256IsSignedAndValidatedByTheLibraryAndByXmlsec(): void
    {
        $this->useCertificate($this->createCertificate(['private_key_type' => OPENSSL_KEYTYPE_DSA, 'private_key_bits' => 2048]));

        $signed = $this->service->signXml(self::XML, $this->certificate, [
            'reference' => 'A',
            'signature_algorithm' => 'dsa-sha256',
            'digest_algorithm' => 'sha256',
        ]);

        $this->assertStringNotContainsString('KeyValue', $signed);
        $results = $this->service->validateXml($signed);
        $this->assertTrue($results[0]->isValid(), (string) $results[0]->getError()?->getMessage());
        $this->assertTrue($this->verifyWithXmlsec($signed));
    }

    public function testDsaWithSha1IsSignedAndValidatedByTheLibraryAndByXmlsec(): void
    {
        $certificate = $this->createDsaCertificateWithOrder160();
        if ($certificate === null) {
            $this->markTestSkipped('OpenSSL can not make a DSA key with an order of 160 bits.');
        }
        $this->useCertificate($certificate);

        $signed = $this->service->signXml(self::XML, $this->certificate, [
            'reference' => 'A',
            'signature_algorithm' => 'dsa-sha1',
        ]);

        $results = $this->service->validateXml($signed);
        $this->assertTrue($results[0]->isValid(), (string) $results[0]->getError()?->getMessage());
        $this->assertTrue($this->verifyWithXmlsec($signed));
    }

    public function testDsaThatXmlsecSignsIsValidatedByTheLibrary(): void
    {
        $certificate = $this->createDsaCertificateWithOrder160();
        if ($certificate === null) {
            $this->markTestSkipped('OpenSSL can not make a DSA key with an order of 160 bits.');
        }
        $this->useCertificate($certificate);
        $template = '<Root><Doc ID="A"><V>1</V></Doc>'
            . $this->template('', self::SIGNATURE_URIS['dsa-sha1'], self::C14N, [
                ['#A', self::DIGESTS['sha1'], [[self::C14N, '']]],
            ])
            . '</Root>';

        $signed = $this->signWithXmlsec($template);

        $results = $this->service->validateXml($signed);
        $this->assertTrue($results[0]->isValid(), (string) $results[0]->getError()?->getMessage());
    }

    /**
     * @return array<string, array{string, array<string, mixed>}>
     */
    public static function mismatchProvider(): array
    {
        return [
            'rsa algorithm with an elliptic curve key' => ['rsa-sha256', ['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']],
            'ecdsa algorithm with an rsa key' => ['ecdsa-sha256', ['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]],
            'dsa algorithm with an rsa key' => ['dsa-sha256', ['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]],
        ];
    }

    /**
     * @param array<string, mixed> $key
     */
    #[DataProvider('mismatchProvider')]
    public function testAnAlgorithmThatIsNotTheOneOfTheKeyIsAnError(string $algorithm, array $key): void
    {
        $certificate = $this->createCertificate($key);

        $this->expectException(SignatureException::class);
        $this->expectExceptionMessage('is not the one of the type of key of the certificate');

        $this->service->signXml(self::XML, $certificate, [
            'reference' => 'A',
            'signature_algorithm' => $algorithm,
        ]);
    }

    public function testTheExclusiveCanonicalizationOfTheSignedInfoIsSignedAndValidated(): void
    {
        $signed = $this->service->signXml(self::XML, $this->certificate, [
            'reference' => 'A',
            'canonicalization_method' => 'exc_c14n',
            'signature_prefix' => 'ds',
        ]);

        $this->assertSame(
            Algorithms::EXC_C14N,
            $this->attribute($signed, '//*[local-name()="CanonicalizationMethod"]', 'Algorithm')
        );
        $results = $this->service->validateXml($signed);
        $this->assertTrue($results[0]->isValid(), (string) $results[0]->getError()?->getMessage());
        $this->assertTrue($this->verifyWithXmlsec($signed));
    }

    public function testTheOptionsThatAreTheDefaultsGiveTheSameSignatureThatNoOptionsGive(): void
    {
        $default = $this->service->signXml(self::XML, $this->certificate, ['reference' => 'A']);

        $explicit = $this->service->signXml(self::XML, $this->certificate, [
            'reference' => 'A',
            'digest_algorithm' => 'sha1',
            'signature_algorithm' => 'rsa-sha1',
            'canonicalization_method' => 'c14n',
            'objects' => [],
            'include_certificate_chain' => false,
        ]);
        $withReferences = $this->service->signXml(self::XML, $this->certificate, [
            'references' => [['uri' => '#A']],
        ]);

        $this->assertSame($default, $explicit);
        $this->assertSame($default, $withReferences);
    }

    public function testTheWholeDocumentWithoutOptionsAndWithItsReferenceIsTheSameSignature(): void
    {
        $default = $this->service->signXml(self::XML, $this->certificate);

        $withReferences = $this->service->signXml(self::XML, $this->certificate, [
            'references' => [['uri' => '']],
        ]);

        $this->assertSame($default, $withReferences);
    }

    public function testTheDefaultAlgorithmsAreTheOnesTheSignatureAlwaysHad(): void
    {
        $signed = $this->service->signXml(self::XML, $this->certificate, ['reference' => 'A']);

        $this->assertSame(
            self::SIGNATURE_URIS['rsa-sha1'],
            $this->attribute($signed, '//*[local-name()="SignatureMethod"]', 'Algorithm')
        );
        $this->assertSame(
            self::DIGEST_URIS['sha1'],
            $this->attribute($signed, '//*[local-name()="DigestMethod"]', 'Algorithm')
        );
        $this->assertSame(
            self::C14N,
            $this->attribute($signed, '//*[local-name()="CanonicalizationMethod"]', 'Algorithm')
        );
    }

    public function testTheAlgorithmsAreFoundByTheirUri(): void
    {
        $this->assertSame('sha256', Algorithms::hashByUri(self::DIGEST_URIS['sha256']));
        $this->assertNull(Algorithms::hashByUri('urn:unknown'));
        $this->assertSame(
            OPENSSL_KEYTYPE_EC,
            Algorithms::signatureByUri(self::SIGNATURE_URIS['ecdsa-sha384'])['key'] ?? null
        );
        $this->assertNull(Algorithms::signatureByUri('urn:unknown'));
    }
}
