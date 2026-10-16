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

use Derafu\Certificate\Exception\CertificateException;
use Derafu\Signature\Exception\SignatureException;
use Derafu\Signature\Service\SignatureGenerator;
use Derafu\Signature\Service\SignatureService;
use Derafu\Signature\Service\SignatureValidator;
use Derafu\Signature\Signature;
use Derafu\Signature\SignatureValidationResult;
use Derafu\Signature\Translation\SignatureTranslationResourceProvider;
use Derafu\TestsSignature\Support\ReadsFixtures;
use Derafu\Translation\Contract\TranslatableInterface;
use Derafu\Translation\TranslatorFactory;
use Derafu\Xml\Exception\XmlException;
use Derafu\Xml\Service\XmlDecoder;
use Derafu\Xml\Service\XmlEncoder;
use Derafu\Xml\Service\XmlService;
use Derafu\Xml\Service\XmlValidator;
use Derafu\Xml\XmlDocument;
use LogicException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Symfony\Component\Translation\Translator;

/**
 * The exceptions of the package are translatable exceptions like any other:
 * what they say is their message. What went wrong in detail (the errors of
 * OpenSSL) is data that they carry, not text that is added to the message.
 */
#[CoversClass(SignatureException::class)]
#[CoversClass(SignatureGenerator::class)]
#[CoversClass(SignatureValidator::class)]
#[CoversClass(SignatureService::class)]
#[CoversClass(SignatureValidationResult::class)]
#[CoversClass(Signature::class)]
#[CoversClass(SignatureTranslationResourceProvider::class)]
final class SignatureExceptionTest extends TestCase
{
    use ReadsFixtures;

    private string $fixturesDir;

    private SignatureGenerator $generator;

    private SignatureValidator $validator;

    protected function setUp(): void
    {
        $this->fixturesDir = __DIR__ . '/../fixtures';

        $xmlService = new XmlService(
            new XmlEncoder(),
            new XmlDecoder(),
            new XmlValidator()
        );
        $this->generator = new SignatureGenerator($xmlService);
        $this->validator = new SignatureValidator($this->generator, $xmlService);
    }

    private function translator(): Translator
    {
        return TranslatorFactory::create('es', [], [new SignatureTranslationResourceProvider()]);
    }

    public function testItIsAnExceptionOfCertificatesAndTranslatable(): void
    {
        $exception = new SignatureException('Could not sign the data.');

        $this->assertInstanceOf(CertificateException::class, $exception);
        $this->assertInstanceOf(TranslatableInterface::class, $exception);
        $this->assertSame('Could not sign the data.', $exception->getMessage());
    }

    public function testItIsTranslatedIntoTheLanguageOfTheTranslator(): void
    {
        $exception = new SignatureException(['The electronic signature of the `SignedInfo` node of the XML for the reference "{reference}" is not valid.', 'reference' => '#A1']);

        $this->assertSame(
            'The electronic signature of the `SignedInfo` node of the XML for the reference "#A1" is not valid.',
            $exception->getMessage()
        );
        $this->assertSame(
            'La firma electrónica del nodo `SignedInfo` del XML para la referencia "#A1" no es válida.',
            $exception->trans($this->translator())
        );
    }

    public function testItKeepsTheCodeThePreviousThrowableAndTheErrors(): void
    {
        $previous = new RuntimeException('previous');
        $exception = new SignatureException('Could not sign the data.', 7, $previous, ['one']);

        $this->assertSame(7, $exception->getCode());
        $this->assertSame($previous, $exception->getPrevious());
        $this->assertSame(['one'], $exception->getErrors());
    }

    public function testTheErrorsOfOpensslAreDataAndNotPartOfTheMessage(): void
    {
        try {
            @$this->generator->sign('data', 'invalid private key');
            $this->fail('It should have failed.');
        } catch (SignatureException $e) {
            $this->assertSame('Could not sign the data.', $e->getMessage());
            $this->assertNotSame([], $e->getErrors());
            $this->assertSame(
                'No fue posible firmar los datos.',
                $e->trans($this->translator())
            );
        }
    }

    public function testAnXmlWithoutSignaturesHasATranslatableError(): void
    {
        $xml = $this->readFixture($this->fixturesDir . '/unsigned.xml');

        try {
            $this->validator->validateXml($xml);
            $this->fail('It should have failed.');
        } catch (SignatureException $e) {
            $this->assertSame('No signatures were found in the XML to validate.', $e->getMessage());
            $this->assertSame(
                'No se encontraron firmas para validar en el XML.',
                $e->trans($this->translator())
            );
        }
    }

    public function testAReferenceThatIsNotInTheXmlHasATranslatableError(): void
    {
        try {
            $this->generator->generateXmlDigestValue(new XmlDocument(), '#nope');
            $this->fail('It should have failed.');
        } catch (XmlException $e) {
            $this->assertSame('No element with ID "nope" was found in the XML document.', $e->getMessage());
            $this->assertSame(
                'No se encontró ningún elemento con ID "nope" en el documento XML.',
                $e->trans($this->translator())
            );
        }
    }

    public function testTheErrorOfAnInvalidSignatureIsTranslatableInTheResult(): void
    {
        $xml = $this->readFixture($this->fixturesDir . '/invalid_signature_value.xml');

        $results = $this->validator->validateXml($xml);

        $errors = array_filter(array_map(fn ($r) => $r->getError(), $results));
        $this->assertNotSame([], $errors);
        foreach ($errors as $error) {
            $this->assertInstanceOf(TranslatableInterface::class, $error);
            $this->assertNotSame($error->getMessage(), $error->trans($this->translator()));
        }
    }

    public function testTheLogicErrorsAreTranslatable(): void
    {
        try {
            (new Signature())->getXml();
            $this->fail('It should have failed.');
        } catch (LogicException $e) {
            $this->assertInstanceOf(TranslatableInterface::class, $e);
            $this->assertSame('The Xml instance is not available in Signature.', $e->getMessage());
            $this->assertSame(
                'La instancia de Xml no está disponible en Signature.',
                $e->trans($this->translator())
            );
        }
    }
}
