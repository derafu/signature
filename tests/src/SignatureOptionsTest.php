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

use Derafu\Config\Contract\OptionsInterface;
use Derafu\Config\Options;
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
use Derafu\TestsSignature\Support\UsesXmlsec;
use Derafu\Translation\TranslatorFactory;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Symfony\Component\OptionsResolver\Exception\InvalidOptionsException;
use Symfony\Component\OptionsResolver\Exception\UndefinedOptionsException;

/**
 * The options of `signXml()`: the ones that are not given have their default
 * value, the ones that are not valid are an error of the signature, and they
 * are valid only for the signature that they are given to.
 */
#[CoversClass(Signature::class)]
#[CoversClass(SignatureService::class)]
#[CoversClass(SignatureGenerator::class)]
#[CoversClass(SignatureValidator::class)]
#[CoversClass(SignatureValidationResult::class)]
#[CoversClass(SignatureException::class)]
#[CoversClass(SignatureTranslationResourceProvider::class)]
#[CoversClass(ReferenceTarget::class)]
#[CoversClass(SignatureElements::class)]
#[UsesClass(Algorithms::class)]
#[UsesClass(RawSignature::class)]
#[UsesClass(ReferenceData::class)]
#[UsesClass(SignatureOptions::class)]
final class SignatureOptionsTest extends TestCase
{
    use UsesXmlsec;

    private const XML = "<Root>\n  <Doc ID=\"A\">\n    <V>1</V>\n  </Doc>\n</Root>\n";

    protected function setUp(): void
    {
        $this->createService();
    }

    /**
     * Gives the text of the signature that was signed (it is the last element
     * of the document), with or without the prefix.
     */
    private function signature(string $signed): string
    {
        $signature = preg_replace('#^.*?(<(?:\w+:)?Signature\b.*</(?:\w+:)?Signature>).*$#s', '$1', $signed);
        $this->assertIsString($signature);

        return $signature;
    }

    public function testOptionsThatAreNotGivenHaveTheirDefaultValue(): void
    {
        $withoutOptions = $this->signature($this->service->signXml(self::XML, $this->certificate));
        $empty = $this->signature($this->service->signXml(self::XML, $this->certificate, []));
        $explicit = $this->signature($this->service->signXml(self::XML, $this->certificate, [
            'reference' => null,
            'signature_namespace' => null,
            'include_certificate_chain' => false,
            'signature_prefix' => null,
        ]));

        // The whole document, the namespace of XML Signature, one certificate
        // and no prefix.
        $this->assertStringStartsWith('<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">', $withoutOptions);
        $this->assertStringContainsString('<Reference URI="">', $withoutOptions);
        $this->assertSame(1, substr_count($withoutOptions, '<X509Certificate>'));
        $this->assertStringNotContainsString('<ds:', $withoutOptions);
        $this->assertSame(
            $this->withoutValues($withoutOptions),
            $this->withoutValues($empty)
        );
        $this->assertSame(
            $this->withoutValues($withoutOptions),
            $this->withoutValues($explicit)
        );
    }

    /**
     * The text of a signature without what is calculated (the digest, the
     * signature and the certificate), to compare what is written.
     */
    private function withoutValues(string $signature): string
    {
        return (string) preg_replace(
            '#<(DigestValue|SignatureValue|Modulus|Exponent|X509Certificate)>[^<]*</\1>#s',
            '<$1/>',
            $signature
        );
    }

    public function testEachOption(): void
    {
        $reference = $this->signature($this->service->signXml(self::XML, $this->certificate, ['reference' => 'A']));
        $namespace = $this->signature($this->service->signXml(self::XML, $this->certificate, [
            'signature_namespace' => 'http://example.com/signature',
        ]));
        $chain = $this->signature($this->service->signXml(self::XML, $this->certificate, [
            'include_certificate_chain' => true,
        ]));
        $prefix = $this->signature($this->service->signXml(self::XML, $this->certificate, ['signature_prefix' => 'ds']));

        $this->assertStringContainsString('<Reference URI="#A">', $reference);
        $this->assertStringStartsWith('<Signature xmlns="http://example.com/signature">', $namespace);
        $this->assertGreaterThan(1, substr_count($chain, '<X509Certificate>'));
        $this->assertStringStartsWith('<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">', $prefix);
    }

    /**
     * @return array<string, array{OptionsInterface}>
     */
    public static function optionsContainerProvider(): array
    {
        // The container of another schema has the options that the signature
        // knows, and it is validated with the schema of the signature.
        return [
            'options without schema' => [new Options(['reference' => 'A', 'signature_prefix' => 'ds'])],
            'options with another schema' => [new Options(
                ['reference' => 'A', 'signature_prefix' => 'ds'],
                ['reference' => ['types' => 'string'], 'signature_prefix' => ['types' => 'string']]
            )],
        ];
    }

    /**
     * The options can be given as a container, and the signature is the same
     * as with an array.
     */
    #[DataProvider('optionsContainerProvider')]
    public function testOptionsAreGivenAsAContainer(OptionsInterface $options): void
    {
        $expected = $this->service->signXml(self::XML, $this->certificate, ['reference' => 'A', 'signature_prefix' => 'ds']);

        $signed = $this->service->signXml(self::XML, $this->certificate, $options);

        $this->assertSame($expected, $signed);
    }

    /**
     * A container is validated with the schema of the signature: an option that
     * it does not know is not valid, wherever the container comes from.
     */
    public function testContainerWithAnOptionThatTheSignatureDoesNotKnowIsNotValid(): void
    {
        $options = new Options(['reference' => 'A', 'other' => 1]);

        $this->expectException(SignatureException::class);

        $this->service->signXml(self::XML, $this->certificate, $options);
    }

    /**
     * @return array<string, array{array<string, mixed>, class-string<\Throwable>, string}>
     */
    public static function invalidOptionsProvider(): array
    {
        return [
            'an option that does not exist' => [['unknown' => 1], UndefinedOptionsException::class, 'unknown'],
            'the name of the old parameter' => [['signaturePrefix' => 'ds'], UndefinedOptionsException::class, 'signaturePrefix'],
            'a reference that is not text' => [['reference' => 5], InvalidOptionsException::class, 'reference'],
            'a prefix that is not text' => [['signature_prefix' => true], InvalidOptionsException::class, 'signature_prefix'],
            'a namespace that is not text' => [['signature_namespace' => []], InvalidOptionsException::class, 'signature_namespace'],
            'a chain that is not a bool' => [['include_certificate_chain' => 'yes'], InvalidOptionsException::class, 'include_certificate_chain'],
        ];
    }

    /**
     * @param array<string, mixed> $options
     * @param class-string<\Throwable> $previous
     */
    #[DataProvider('invalidOptionsProvider')]
    public function testOptionsThatAreNotValidAreAnErrorOfTheSignature(array $options, string $previous, string $name): void
    {
        try {
            $this->service->signXml(self::XML, $this->certificate, $options);
            $this->fail('An option that is not valid must be an error.');
        } catch (SignatureException $exception) {
            $this->assertStringStartsWith('The options of the signature are not valid: ', $exception->getMessage());
            $this->assertStringContainsString($name, $exception->getMessage());
            $this->assertInstanceOf($previous, $exception->getPrevious());

            $translator = TranslatorFactory::create('es', [], [new SignatureTranslationResourceProvider()]);
            $this->assertStringStartsWith('Las opciones de la firma no son válidas: ', $exception->trans($translator));
        }
    }

    public function testOptionsAreValidOnlyForTheSignatureThatTheyAreGivenTo(): void
    {
        $options = new Options(['reference' => 'A', 'signature_prefix' => 'ds', 'include_certificate_chain' => true]);

        $first = $this->service->signXml(self::XML, $this->certificate, $options);
        $second = $this->service->signXml(self::XML, $this->certificate);
        $third = $this->service->signXml(self::XML, $this->certificate, ['reference' => 'A']);

        $this->assertStringContainsString('<ds:Signature', $first);
        $this->assertGreaterThan(1, substr_count($first, '<ds:X509Certificate>'));
        // The next signatures do not have what the first one had.
        $this->assertStringNotContainsString('ds:', $second);
        $this->assertStringContainsString('<Reference URI="">', $second);
        $this->assertStringNotContainsString('ds:', $third);
        $this->assertSame(1, substr_count($third, '<X509Certificate>'));
        // The options that were given are not changed.
        $this->assertSame(
            ['reference' => 'A', 'signature_prefix' => 'ds', 'include_certificate_chain' => true],
            $options->all()
        );
    }

    public function testTheSignatureThatIsSignedWithOptionsIsValid(): void
    {
        $signed = $this->service->signXml(self::XML, $this->certificate, [
            'reference' => 'A',
            'signature_prefix' => 'ds',
            'include_certificate_chain' => true,
        ]);

        $results = $this->service->validateXml($signed);

        $this->assertCount(1, $results);
        $this->assertTrue($results[0]->isValid());
    }
}
