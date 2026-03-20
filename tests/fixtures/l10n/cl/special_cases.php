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

    // Cases for testSignatureWithSpecialCharacters().
    'testSignatureWithSpecialCharacters' => [
        // Test case with Latin special characters and XML entities.
        'latin_special_characters' => [
            'data' => [
                'Document' => [
                    '@attributes' => ['version' => '1.0'],
                    'Header' => [
                        '@attributes' => ['ID' => 'TestDoc'],
                        'Company' => [
                            'Name' => 'Empresa Óptica Ltda.',
                            'Address' => 'Av. Providencia 1234, Ñuñoa',
                            'Description' => 'Firma electrónica con ñáéíóúü & caracteres especiales',
                        ],
                        'Details' => [
                            'Item' => 'Producto con áéíóú ñ',
                            'Comment' => 'Comentario con <tags> y "comillas"',
                            'SpecialChars' => 'Caracteres: ñáéíóúü',
                        ],
                    ],
                ],
            ],
            'reference' => 'TestDoc',
            'expectedException' => null,
        ],

        // Test case with XML entities and special characters in attributes.
        'xml_entities_and_attributes' => [
            'data' => [
                'Document' => [
                    '@attributes' => [
                        'version' => '1.0',
                        'description' => 'Documento con ñáéíóú',
                    ],
                    'Header' => [
                        '@attributes' => ['ID' => 'TestDoc2'],
                        'Company' => [
                            'Name' => 'Empresa & Hijos Ltda.',
                            'Address' => 'Av. Providencia 1234, Ñuñoa',
                            'Description' => 'Firma con &amp; &lt; &gt; &quot; &apos;',
                        ],
                        'Details' => [
                            'Item' => 'Producto con <tags> y "comillas"',
                            'Comment' => 'Comentario con & caracteres especiales',
                        ],
                    ],
                ],
            ],
            'reference' => 'TestDoc2',
            'expectedException' => null,
        ],

        // Test case with mixed content and nested elements.
        'mixed_content_and_nesting' => [
            'data' => [
                'Document' => [
                    '@attributes' => ['version' => '1.0'],
                    'Header' => [
                        '@attributes' => ['ID' => 'TestDoc3'],
                        'Company' => [
                            'Name' => 'Empresa Óptica Ltda.',
                            'Address' => [
                                'Street' => 'Av. Providencia 1234',
                                'City' => 'Ñuñoa',
                                'Country' => 'Chile',
                            ],
                            'Description' => 'Firma electrónica con ñáéíóúü',
                        ],
                        'Details' => [
                            'Items' => [
                                'Item' => [
                                    ['@attributes' => ['id' => '1'], '@value' => 'Producto con áéíóú'],
                                    ['@attributes' => ['id' => '2'], '@value' => 'Producto con ñ'],
                                    ['@attributes' => ['id' => '3'], '@value' => 'Producto con & < > " \''],
                                ],
                            ],
                        ],
                    ],
                ],
            ],
            'reference' => 'TestDoc3',
            'expectedException' => null,
        ],

        // Test case with special characters in element values only.
        'special_characters_in_values' => [
            'data' => [
                'Document' => [
                    '@attributes' => ['version' => '1.0'],
                    'Header' => [
                        '@attributes' => ['ID' => 'TestDoc4'],
                        'Company' => [
                            'Name' => 'Empresa Óptica Ltda.',
                            'Address' => 'Av. Providencia 1234, Ñuñoa',
                            'Description' => 'Firma electrónica con ñáéíóúü',
                        ],
                        'Details' => [
                            'Item' => 'Producto con áéíóú ñ',
                            'Comment' => 'Comentario con caracteres especiales',
                        ],
                    ],
                ],
            ],
            'reference' => 'TestDoc4',
            'expectedException' => null,
        ],

        // Test case with special characters in attributes only.
        'special_characters_in_attributes' => [
            'data' => [
                'Document' => [
                    '@attributes' => [
                        'version' => '1.0',
                        'description' => 'Documento con ñáéíóú',
                        'company' => 'Empresa Óptica Ltda.',
                    ],
                    'Header' => [
                        '@attributes' => [
                            'ID' => 'TestDoc5',
                            'title' => 'Documento con ñáéíóú',
                            'author' => 'Autor con ñáéíóú',
                        ],
                        'Company' => [
                            'Name' => 'Empresa Ltda.',
                            'Address' => 'Av. Providencia 1234',
                        ],
                        'Details' => [
                            'Item' => 'Producto estándar',
                            'Comment' => 'Comentario estándar',
                        ],
                    ],
                ],
            ],
            'reference' => 'TestDoc5',
            'expectedException' => null,
        ],
    ],

];
