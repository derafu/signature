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

use Derafu\Certificate\Contract\OpenSslInterface;
use Derafu\Certificate\Exception\CertificateException;
use Derafu\Certificate\Service\CertificateFaker;
use Derafu\Certificate\Service\CertificateLoader;
use Derafu\Signature\Exception\SignatureException;
use Derafu\Signature\Service\SignatureGenerator;
use Derafu\Signature\Service\SignatureValidator;
use Derafu\Translation\Contract\TranslatableInterface;
use Derafu\Translation\TranslatableMessage;
use Derafu\Xml\Service\XmlDecoder;
use Derafu\Xml\Service\XmlEncoder;
use Derafu\Xml\Service\XmlService;
use Derafu\Xml\Service\XmlValidator;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

/**
 * The signatures are made and verified by the OpenSSL service, the only one that
 * calls OpenSSL. A failure of it is a failure of the signature, with the errors
 * of that call and not of another one; and a signature that is not valid is a
 * result, that leaves nothing behind.
 */
#[CoversClass(SignatureGenerator::class)]
#[CoversClass(SignatureValidator::class)]
#[CoversClass(SignatureException::class)]
final class SignatureOpenSslTest extends TestCase
{
    private XmlService $xmlService;

    protected function setUp(): void
    {
        $this->xmlService = new XmlService(
            new XmlEncoder(),
            new XmlDecoder(),
            new XmlValidator()
        );
    }

    private function generator(?OpenSslInterface $openSsl = null): SignatureGenerator
    {
        return $openSsl === null
            ? new SignatureGenerator($this->xmlService)
            : new SignatureGenerator($this->xmlService, $openSsl)
        ;
    }

    private function validator(?OpenSslInterface $openSsl = null): SignatureValidator
    {
        $generator = $this->generator();

        return $openSsl === null
            ? new SignatureValidator($generator, $this->xmlService)
            : new SignatureValidator($generator, $this->xmlService, $openSsl)
        ;
    }

    private function error(string $text): TranslatableInterface
    {
        return new TranslatableMessage('OpenSSL: {text}', ['text' => $text], domain: 'errors');
    }

    public function testASignatureThatFailsIsASignatureExceptionWithTheErrorsOfItsCall(): void
    {
        $error = $this->error('of the call');
        $failure = new CertificateException('OpenSSL could not sign the data.', errors: [$error]);
        $openSsl = $this->createStub(OpenSslInterface::class);
        $openSsl->method('sign')->willThrowException($failure);

        try {
            $this->generator($openSsl)->sign('data', 'private key');
            $this->fail('It should have failed.');
        } catch (SignatureException $e) {
            $this->assertSame('Could not sign the data.', $e->getMessage());
            $this->assertSame([$error], $e->getErrors());
            $this->assertSame($failure, $e->getPrevious());
        }
    }

    public function testAVerificationThatFailsIsASignatureExceptionWithTheErrorsOfItsCall(): void
    {
        $error = $this->error('of the call');
        $failure = new CertificateException('OpenSSL could not verify the signature.', errors: [$error]);
        $openSsl = $this->createStub(OpenSslInterface::class);
        $openSsl->method('verify')->willThrowException($failure);

        try {
            $this->validator($openSsl)->validate('data', 'c2lnbmF0dXJl', 'certificate');
            $this->fail('It should have failed.');
        } catch (SignatureException $e) {
            $this->assertSame(
                'An error occurred while verifying the electronic signature of the data.',
                $e->getMessage()
            );
            $this->assertSame([$error], $e->getErrors());
            $this->assertSame($failure, $e->getPrevious());
        }
    }

    public function testTheGeneratorGivesTheServiceWhatToSignAndGivesBackTheSignatureInBase64(): void
    {
        $openSsl = $this->createMock(OpenSslInterface::class);
        $openSsl->expects($this->once())
            ->method('sign')
            ->with('data', 'private key', OPENSSL_ALGO_SHA1)
            ->willReturn('signature')
        ;

        $this->assertSame(base64_encode('signature'), $this->generator($openSsl)->sign('data', 'private key'));
    }

    public function testTheValidatorGivesTheServiceTheSignatureAsItIsNotInBase64(): void
    {
        $openSsl = $this->createMock(OpenSslInterface::class);
        $openSsl->expects($this->once())
            ->method('verify')
            ->with('data', 'signature', $this->stringContains('BEGIN CERTIFICATE'), OPENSSL_ALGO_SHA1)
            ->willReturn(true)
        ;

        $this->assertTrue(
            $this->validator($openSsl)->validate('data', base64_encode('signature'), 'certificate')
        );
    }

    public function testTheErrorsOfASignatureThatFailsWithTheRealServiceAreTheOnesOfOpenssl(): void
    {
        try {
            $this->generator()->sign('data', 'not a private key');
            $this->fail('It should have failed.');
        } catch (SignatureException $e) {
            // The warning of PHP, that is not emitted but is an error of the call.
            $this->assertStringContainsString(
                'Supplied key param cannot be coerced into a private key',
                implode(' ', array_map('strval', $e->getErrors()))
            );
        }
    }

    /**
     * An invalid signature is a result (`false`), and OpenSSL leaves errors for
     * it. They are not left in the queue of the process, and they are not in the
     * errors of the next exception.
     */
    public function testAnInvalidSignatureLeavesNothingBehind(): void
    {
        $certificate = (new CertificateFaker(new CertificateLoader()))->createFake();
        $validator = $this->validator();
        $signature = $this->generator()->sign('hello', $certificate->getPrivateKey());

        $this->assertFalse($validator->validate('tampered', $signature, $certificate->getCertificate()));
        $this->assertFalse(openssl_error_string());

        try {
            $validator->validateXml('<?xml version="1.0"?><Doc><A>1</A></Doc>');
            $this->fail('It should have failed.');
        } catch (SignatureException $e) {
            $this->assertSame('No signatures were found in the XML to validate.', $e->getMessage());
            $this->assertSame([], $e->getErrors());
        }
    }
}
