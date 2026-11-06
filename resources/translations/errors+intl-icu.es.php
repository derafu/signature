<?php

declare(strict_types=1);

/**
 * Derafu: Signature - Library for digital signatures.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

return [
    // SignatureGenerator.
    'Could not sign the data.' =>
        'No fue posible firmar los datos.',
    'Could not get the documentElement from the XML to sign (possible malformed XML).' =>
        'No fue posible obtener el elemento raíz del XML a firmar (posiblemente el XML está mal formado).',
    'No element with ID "{id}" was found in the XML document.' =>
        'No se encontró ningún elemento con ID "{id}" en el documento XML.',
    'It is not possible to generate the signature of the Signature node if the digital certificate is not assigned.' =>
        'No es posible generar la firma del nodo Signature si no se ha asignado el certificado digital.',
    'SignedInfo node is missing from the generated Signature XML.' =>
        'Falta el nodo SignedInfo en el XML de la firma generada.',
    // SignatureGenerator: options.
    'The options of the signature are not valid: {detail}' =>
        'Las opciones de la firma no son válidas: {detail}',
    // Signature.
    'The namespace prefix "{prefix}" of the signature is not valid.' =>
        'El prefijo de espacio de nombres "{prefix}" de la firma no es válido.',
    // SignatureValidator.
    'An error occurred while verifying the electronic signature of the data.' =>
        'Ocurrió un error al verificar la firma electrónica de los datos.',
    'Could not get the documentElement from the XML to validate its signature (possible malformed XML).' =>
        'No fue posible obtener el elemento raíz del XML para validar su firma (posiblemente el XML está mal formado).',
    'No signatures were found in the XML to validate.' =>
        'No se encontraron firmas para validar en el XML.',
    'The DigestValue that comes in the XML "{xml}" for the reference "{reference}" does not match the calculated value when validating "{calculated}". The data of the reference could have been manipulated after being signed.' =>
        'El DigestValue que viene en el XML "{xml}" para la referencia "{reference}" no coincide con el valor calculado al validar "{calculated}". Los datos de la referencia pudieron ser manipulados después de ser firmados.',
    'The reference "{reference}" points to a resource that is not in the document, and no resource resolver was given.' =>
        'La referencia "{reference}" apunta a un recurso que no está en el documento, y no se indicó un resolutor de recursos.',
    'The digest algorithm "{algorithm}" of the signature is not supported.' =>
        'El algoritmo de digest "{algorithm}" de la firma no está soportado.',
    'The signature element with the transforms of the reference was not found in the XML to validate.' =>
        'No se encontró en el XML a validar el elemento de la firma con las transformaciones de la referencia.',
    'The DigestValue is missing from the signature node.' =>
        'Falta el DigestValue en el nodo de la firma.',
    'The SignatureValue is missing from the signature node.' =>
        'Falta el SignatureValue en el nodo de la firma.',
    'The X509Certificate is missing from the signature node.' =>
        'Falta el X509Certificate en el nodo de la firma.',
    'The electronic signature of the `SignedInfo` node of the XML for the reference "{reference}" is not valid.' =>
        'La firma electrónica del nodo `SignedInfo` del XML para la referencia "{reference}" no es válida.',
    // SignatureGenerator: location, references and algorithms.
    'The XPath "{xpath}" of the location of the signature is not valid.' =>
        'El XPath "{xpath}" de la ubicación de la firma no es válido.',
    'The XPath "{xpath}" of the location of the signature selects {count} elements, and it must select one.' =>
        'El XPath "{xpath}" de la ubicación de la firma selecciona {count} elementos, y debe seleccionar uno.',
    'The signature can not be placed before or after the root element.' =>
        'La firma no se puede ubicar antes ni después del elemento raíz.',
    'The signature has a reference to a resource that is not in the document, and it has no resource resolver.' =>
        'La firma tiene una referencia a un recurso que no está en el documento, y no tiene un resolutor de recursos.',
    'The signature algorithm "{algorithm}" is not the one of the type of key of the certificate.' =>
        'El algoritmo de firma "{algorithm}" no es el del tipo de clave del certificado.',
    // RawSignature.
    'The signature is not a sequence of two integers in DER.' =>
        'La firma no es una secuencia de dos enteros en DER.',
    'The signature is not the concatenation of two integers of the same size.' =>
        'La firma no es la concatenación de dos enteros del mismo tamaño.',
    // ReferenceData.
    'The XPath of a reference to a resource that is not in the document can not use here().' =>
        'El XPath de una referencia a un recurso que no está en el documento no puede usar here().',
    // Signature.
    'The Xml instance is not available in Signature.' =>
        'La instancia de Xml no está disponible en Signature.',
];
