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
use Derafu\Signature\Support\RawSignature;
use Derafu\Signature\Translation\SignatureTranslationResourceProvider;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The signatures of ECDSA and DSA in the two forms they have: the DER of
 * OpenSSL and the concatenation of the two integers of XML Signature.
 */
#[CoversClass(RawSignature::class)]
#[CoversClass(SignatureException::class)]
#[CoversClass(SignatureTranslationResourceProvider::class)]
final class RawSignatureTest extends TestCase
{
    /**
     * @return array<string, array{string, int, string}>
     */
    public static function validProvider(): array
    {
        return [
            'integers that need no padding' => [
                "\x30\x06\x02\x01\x05\x02\x01\x07", 1, "\x05\x07",
            ],
            'integers with the high bit, that DER writes with a zero before' => [
                "\x30\x08\x02\x02\x00\x80\x02\x02\x00\xFF", 1, "\x80\xFF",
            ],
            'integers shorter than the size' => [
                "\x30\x06\x02\x01\x05\x02\x01\x07", 3, "\x00\x00\x05\x00\x00\x07",
            ],
        ];
    }

    #[DataProvider('validProvider')]
    public function testASignatureInDerIsTheConcatenationOfItsIntegers(string $der, int $size, string $raw): void
    {
        $this->assertSame($raw, RawSignature::fromDer($der, $size));
    }

    #[DataProvider('validProvider')]
    public function testTheConcatenationOfTheIntegersIsASignatureInDer(string $der, int $size, string $raw): void
    {
        // The DER that is written is the minimal one: the integers have no
        // zeros that are not needed.
        $this->assertSame(RawSignature::fromDer(RawSignature::toDer($raw), $size), $raw);
    }

    public function testTheLongIntegersOfALargeCurveUseTheLongFormOfTheLength(): void
    {
        $raw = random_bytes(66) . random_bytes(66);
        $raw[0] = "\xFF";
        $raw[66] = "\xFF";

        $der = RawSignature::toDer($raw);

        $this->assertSame("\x30\x81", substr($der, 0, 2));
        $this->assertSame($raw, RawSignature::fromDer($der, 66));
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function invalidDerProvider(): array
    {
        return [
            'empty' => ['', 'is not a sequence of two integers in DER'],
            'not a sequence' => ["\x31\x00", 'is not a sequence of two integers in DER'],
            'without length' => ["\x30", 'is not a sequence of two integers in DER'],
            'a length that is not the one of the data' => ["\x30\x05\x02\x01\x05\x02\x01\x07", 'is not a sequence of two integers in DER'],
            'a length of zero bytes in the long form' => ["\x30\x80", 'is not a sequence of two integers in DER'],
            'a length of too many bytes' => ["\x30\x85\x00\x00\x00\x00\x00", 'is not a sequence of two integers in DER'],
            'a long length that does not fit' => ["\x30\x82\x01", 'is not a sequence of two integers in DER'],
            'an element that is not an integer' => ["\x30\x06\x04\x01\x05\x02\x01\x07", 'is not a sequence of two integers in DER'],
            'an integer without content' => ["\x30\x05\x02\x00\x02\x01\x07", 'is not a sequence of two integers in DER'],
            'an integer that goes beyond the data' => ["\x30\x06\x02\x05\x05\x02\x01\x07", 'is not a sequence of two integers in DER'],
            'a second integer that is not one' => ["\x30\x06\x02\x01\x05\x04\x01\x07", 'is not a sequence of two integers in DER'],
            'only one integer' => ["\x30\x03\x02\x01\x05", 'is not a sequence of two integers in DER'],
            'more than two integers' => ["\x30\x09\x02\x01\x05\x02\x01\x07\x02\x01\x09", 'is not a sequence of two integers in DER'],
        ];
    }

    #[DataProvider('invalidDerProvider')]
    public function testADerThatIsNotAPairOfIntegersIsAnError(string $der, string $message): void
    {
        $this->expectException(SignatureException::class);
        $this->expectExceptionMessage($message);

        RawSignature::fromDer($der, 4);
    }

    public function testAnIntegerThatDoesNotFitInTheSizeIsAnError(): void
    {
        $this->expectException(SignatureException::class);
        $this->expectExceptionMessage('is not a sequence of two integers in DER');

        RawSignature::fromDer("\x30\x08\x02\x02\x01\x02\x02\x02\x01\x02", 1);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function invalidRawProvider(): array
    {
        return ['empty' => [''], 'odd' => ['abc']];
    }

    #[DataProvider('invalidRawProvider')]
    public function testARawSignatureThatIsNotTwoIntegersOfTheSameSizeIsAnError(string $raw): void
    {
        $this->expectException(SignatureException::class);
        $this->expectExceptionMessage('is not the concatenation of two integers of the same size');

        RawSignature::toDer($raw);
    }
}
