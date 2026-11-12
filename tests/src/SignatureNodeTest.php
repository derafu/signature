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

use Closure;
use Derafu\Certificate\Contract\CertificateInterface;
use Derafu\Certificate\Service\CertificateFaker;
use Derafu\Certificate\Service\CertificateLoader;
use Derafu\Signature\Signature;
use Derafu\Signature\Support\Algorithms;
use Derafu\Signature\Support\RawSignature;
use Derafu\Signature\Support\ReferenceData;
use Derafu\Signature\Support\SignatureOptions;
use Derafu\Signature\Translation\SignatureTranslationResourceProvider;
use Derafu\TestsSignature\Support\CreatesKeys;
use Derafu\TestsSignature\Support\ReadsData;
use Derafu\Xml\XmlDocument;
use InvalidArgumentException;
use LogicException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

/**
 * The node of the signature, in the details of how it keeps and gives its
 * data: the XML that it has is discarded when the data changes, the
 * references and the certificates have the shape that the encoder needs, and
 * the names of the elements are found with or without a prefix.
 */
#[CoversClass(Signature::class)]
#[UsesClass(Algorithms::class)]
#[UsesClass(RawSignature::class)]
#[UsesClass(ReferenceData::class)]
#[UsesClass(SignatureOptions::class)]
#[UsesClass(SignatureTranslationResourceProvider::class)]
final class SignatureNodeTest extends TestCase
{
    use ReadsData;

    use CreatesKeys;

    private const C14N = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';

    private const ENVELOPED = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';

    private const SHA1 = 'http://www.w3.org/2000/09/xmldsig#sha1';

    private static ?CertificateInterface $fakeCertificate = null;

    private static function certificate(): CertificateInterface
    {
        return self::$fakeCertificate ??= (new CertificateFaker(new CertificateLoader()))->createFake();
    }

    /**
     * @return array<string, array{Closure(Signature): mixed}>
     */
    public static function changeProvider(): array
    {
        $reference = [
            'uri' => '#A', 'id' => null, 'type' => null,
            'digestAlgorithm' => 'd', 'digestValue' => 'v', 'transforms' => [],
        ];
        $object = ['id' => null, 'mimeType' => null, 'encoding' => null, 'content' => 'x'];

        return [
            'the data' => [fn (Signature $s) => $s->setData([])],
            'the canonicalization method' => [fn (Signature $s) => $s->setCanonicalizationMethod('urn:c')],
            'the signature method' => [fn (Signature $s) => $s->setSignatureMethod('urn:s')],
            'the id of the signature' => [fn (Signature $s) => $s->setSignatureId('S1')],
            'the id of the signature value' => [fn (Signature $s) => $s->setSignatureValueId('V1')],
            'the references' => [fn (Signature $s) => $s->setReferences([$reference])],
            'the objects' => [fn (Signature $s) => $s->setObjects([$object])],
            'the signature value' => [fn (Signature $s) => $s->setSignatureValue('signature')],
        ];
    }

    /**
     * The XML of the node is made from its data: when the data changes, the XML
     * that it had is not the one of the node anymore.
     *
     * @param Closure(Signature): mixed $change
     */
    #[DataProvider('changeProvider')]
    public function testTheXmlIsDiscardedWhenTheDataChanges(Closure $change): void
    {
        $signature = new Signature();
        $xml = new XmlDocument();
        $signature->setXml($xml);
        $this->assertSame($xml, $signature->getXml());

        $change($signature);

        $this->expectException(LogicException::class);

        $signature->getXml();
    }

    public function testTheReferenceIsAnIdWithTheHashAndItsTransformIsTheCanonicalization(): void
    {
        foreach (['#Doc1', 'Doc1'] as $reference) {
            $signature = (new Signature())->configureSignatureData('digest', self::certificate(), reference: $reference);
            $node = $this->at($signature->getData(), 'Signature', 'SignedInfo', 'Reference');

            $this->assertSame('#Doc1', $this->at($node, '@attributes', 'URI'));
            $this->assertSame(self::C14N, $this->at($node, 'Transforms', 'Transform', '@attributes', 'Algorithm'));
        }
    }

    public function testTheWholeDocumentIsReferencedWithTheEnvelopedSignatureTransform(): void
    {
        $signature = (new Signature())->configureSignatureData('digest', self::certificate());
        $node = $this->at($signature->getData(), 'Signature', 'SignedInfo', 'Reference');

        $this->assertSame('', $this->at($node, '@attributes', 'URI'));
        $this->assertSame(self::ENVELOPED, $this->at($node, 'Transforms', 'Transform', '@attributes', 'Algorithm'));
    }

    public function testTheSignatureAsAnArrayHasTheValuesOfEachPartOfIt(): void
    {
        $certificate = self::certificate();
        $signature = (new Signature())
            ->configureSignatureData('the digest', $certificate, reference: 'Doc1')
            ->setSignatureValue('the signature')
            ->setCanonicalizationMethod('urn:canonicalization')
            ->setSignatureMethod('urn:signature-method')
        ;

        $array = $signature->toArray();

        $this->assertSame('Doc1', $array['reference']);
        $this->assertSame('urn:canonicalization', $array['canonicalization_method']);
        $this->assertSame('urn:signature-method', $array['signature_method']);
        $this->assertSame(self::SHA1, $array['digest_method']);
        $this->assertSame('the digest', $array['digest_value']);
        $this->assertSame('the signature', $array['signature_value']);
        $this->assertSame($certificate->getModulus(), $array['modulus']);
        $this->assertSame($certificate->getExponent(), $array['exponent']);
        $this->assertSame($certificate->getCertificate(true), $array['certificate']);
        $this->assertSame([], $array['certificate_chain']);
        $this->assertIsArray($array['signer']);
        $this->assertArrayNotHasKey('pkey', $array['signer']);
        $this->assertSame($array, $signature->jsonSerialize());
    }

    public function testASingleCertificateIsATextAndSeveralAreAList(): void
    {
        $certificate = self::certificate();

        $single = (new Signature())->configureSignatureData('digest', $certificate);
        $chained = (new Signature())->configureSignatureData('digest', $certificate, includeCertificateChain: true);

        $this->assertSame($certificate->getCertificate(true), $this->at($single->getData(), 'Signature', 'KeyInfo', 'X509Data', 'X509Certificate'));
        $this->assertSame(
            [$certificate->getCertificate(true), ...$certificate->getCertificateChain(true)],
            $this->at($chained->getData(), 'Signature', 'KeyInfo', 'X509Data', 'X509Certificate')
        );
    }

    public function testTheCertificatesThatAreNotTextAreNotInTheChain(): void
    {
        $signature = (new Signature())->setData(['Signature' => [
            'KeyInfo' => ['X509Data' => ['X509Certificate' => ['first', 123, 'chain']]],
        ]]);

        $this->assertSame('first', $signature->getX509Certificate());
        $this->assertSame(['chain'], $signature->getX509CertificateChain());
    }

    public function testTheSignatureValueIsWrittenInLinesOf64Characters(): void
    {
        $signature = (new Signature())->setSignatureValue(str_repeat('A', 130));

        $this->assertSame(
            str_repeat('A', 64) . "\n" . str_repeat('A', 64) . "\nAA",
            $signature->getSignatureValue()
        );
    }

    public function testTheIdOfTheSignatureValueKeepsTheValue(): void
    {
        $signature = (new Signature())->setSignatureValue('abc')->setSignatureValueId('V1');

        $this->assertSame('abc', $signature->getSignatureValue());
        $this->assertSame(
            ['@attributes' => ['Id' => 'V1'], '@value' => 'abc'],
            $this->at($signature->getData(), 'Signature', 'SignatureValue')
        );

        $signature->setSignatureValueId('V2');

        $this->assertSame('abc', $signature->getSignatureValue());
        $this->assertSame(
            ['@attributes' => ['Id' => 'V2'], '@value' => 'abc'],
            $this->at($signature->getData(), 'Signature', 'SignatureValue')
        );
    }

    public function testTheTransformsOfAReferenceAreAnElementOrAList(): void
    {
        $one = (new Signature())->setReferences([$this->reference([$this->transform(self::C14N)])]);
        $two = (new Signature())->setReferences([$this->reference([$this->transform(self::ENVELOPED), $this->transform(self::C14N)])]);

        $this->assertSame(
            ['@attributes' => ['Algorithm' => self::C14N]],
            $this->at($one->getData(), 'Signature', 'SignedInfo', 'Reference', 'Transforms', 'Transform')
        );
        $this->assertSame(
            [['@attributes' => ['Algorithm' => self::ENVELOPED]], ['@attributes' => ['Algorithm' => self::C14N]]],
            $this->at($two->getData(), 'Signature', 'SignedInfo', 'Reference', 'Transforms', 'Transform')
        );
    }

    public function testWithSeveralReferencesThereIsNoSingleDigestNorReference(): void
    {
        $signature = (new Signature())->setReferences([$this->reference([], '#A'), $this->reference([], '#B')]);

        $this->assertNull($signature->getDigestValue());
        $this->assertNull($signature->getReference());
        $this->assertCount(2, $signature->getReferences());
    }

    public function testTheFirstElementWithTheNameIsTheOneThatIsRead(): void
    {
        $signature = (new Signature())->setData(['Signature' => [
            'x:SignatureValue' => 'first',
            'y:SignatureValue' => 'second',
        ]]);

        $this->assertSame('first', $signature->getSignatureValue());
    }

    public function testAKeyInfoThatIsAListIsNotAProblemForAnotherKindOfKey(): void
    {
        $certificate = $this->createCertificate(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);

        $signature = (new Signature())
            ->setData(['Signature' => ['KeyInfo' => ['one', 'two']]])
            ->configureSignatureData('digest', $certificate)
        ;

        $this->assertNotNull($signature->getX509Certificate());
    }

    public function testAPrefixThatIsNotValidIsAnErrorWithItsName(): void
    {
        try {
            (new Signature())->configureSignatureData('digest', self::certificate(), signaturePrefix: '1a');
            $this->fail('It should have failed.');
        } catch (InvalidArgumentException $e) {
            $this->assertSame('The namespace prefix "1a" of the signature is not valid.', $e->getMessage());
        }
    }

    public function testTheNamespaceThatTheSignatureHadIsTheOneOfTheNewPrefix(): void
    {
        $signature = (new Signature())->setData(['Signature' => [
            '@attributes' => ['xmlns' => 'urn:custom'],
            'SignatureValue' => '',
        ]]);

        $signature->configureSignatureData('digest', self::certificate(), signaturePrefix: 'ds');

        $this->assertSame('urn:custom', $this->at($signature->getData(), 'ds:Signature', '@attributes', 'xmlns:ds'));
    }

    public function testTheAttributesThatTheSignatureHadAreKeptWithTheNewPrefix(): void
    {
        $signature = (new Signature())->setSignatureId('S1');

        $signature->configureSignatureData('digest', self::certificate(), signaturePrefix: 'ds');

        $attributes = $this->at($signature->getData(), 'ds:Signature', '@attributes');
        $this->assertIsArray($attributes);
        $this->assertSame('S1', $attributes['Id'] ?? null);
        $this->assertArrayHasKey('xmlns:ds', $attributes);
        $this->assertArrayNotHasKey('xmlns', $attributes);
    }

    public function testASignatureThatIsNotAnElementIsLeftAsItIsWhenItGetsAPrefix(): void
    {
        $signature = (new Signature())->setData(['Signature' => 'text']);

        $signature->configureSignatureData('digest', self::certificate(), signaturePrefix: 'ds');

        $this->assertArrayNotHasKey('xmlns:ds', (array) ($this->at($signature->getData(), 'ds:Signature')));
    }

    /**
     * @param list<array{algorithm: string, expression: string|null, namespaces: array<string, string>}> $transforms
     * @return array{uri: string, id: string|null, type: string|null, digestAlgorithm: string, digestValue: string, transforms: list<array{algorithm: string, expression: string|null, namespaces: array<string, string>}>}
     */
    private function reference(array $transforms, string $uri = '#A'): array
    {
        return [
            'uri' => $uri, 'id' => null, 'type' => null,
            'digestAlgorithm' => self::SHA1, 'digestValue' => 'v', 'transforms' => $transforms,
        ];
    }

    /**
     * @return array{algorithm: string, expression: string|null, namespaces: array<string, string>}
     */
    private function transform(string $algorithm): array
    {
        return ['algorithm' => $algorithm, 'expression' => null, 'namespaces' => []];
    }
}
