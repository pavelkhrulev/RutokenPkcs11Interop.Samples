﻿namespace RutokenPkcs11Interop.Samples.Common
{
    public static class SampleData
    {
        public static byte[] PublicKeyData_256 => new byte[]
        {
            0x76, 0x25, 0x13, 0x0F, 0x19, 0x17, 0x3D, 0x3B, 0x24, 0xCC, 0xA7, 0xC7, 0x72, 0xB3, 0x5D, 0x83,
            0xB0, 0xBB, 0x42, 0xC9, 0x66, 0xD5, 0xC1, 0x5A, 0x0A, 0x9F, 0xD4, 0x24, 0xF0, 0x46, 0xB2, 0xCD,
            0x85, 0xDD, 0xC5, 0x73, 0xAE, 0x72, 0x8D, 0x6F, 0xC8, 0x9C, 0xE2, 0x5B, 0x89, 0x05, 0xE8, 0x9D,
            0x75, 0x93, 0xBF, 0xE9, 0x38, 0xC3, 0x43, 0x27, 0x09, 0x59, 0x7E, 0x7D, 0x51, 0xA8, 0x35, 0x53
        };

        public static byte[] PublicKeyData_512 => new byte[]
        {
            0xFC, 0xD5, 0xD3, 0x91, 0xEF, 0x58, 0x66, 0x50, 0x26, 0x59, 0x6C, 0x71, 0xE5, 0x89, 0x35, 0xC7,
            0x35, 0x71, 0x28, 0xA4, 0xAD, 0x3C, 0xD5, 0x0A, 0xA3, 0xF8, 0xB1, 0xD9, 0xC1, 0x77, 0xB3, 0x17,
            0x65, 0x0C, 0x7E, 0x6E, 0x11, 0x12, 0xC2, 0x62, 0xB3, 0xDF, 0x43, 0x32, 0x54, 0xB4, 0x7C, 0x7D,
            0xF3, 0x3C, 0x1F, 0xD7, 0xEA, 0x02, 0xE7, 0x70, 0x15, 0xCC, 0xFC, 0x28, 0xC6, 0xAE, 0x91, 0x29,
            0x58, 0xFB, 0x75, 0x14, 0x7B, 0x0E, 0x99, 0x59, 0xF9, 0x4B, 0xE9, 0x80, 0xA5, 0xBB, 0x18, 0x8E,
            0xED, 0x43, 0xCC, 0x8D, 0x9E, 0x39, 0x14, 0x6A, 0xBA, 0xC7, 0x5F, 0xFF, 0x02, 0x4C, 0x1C, 0x9E,
            0xFE, 0x71, 0xF2, 0xC3, 0xFD, 0xD6, 0x1C, 0x76, 0xBE, 0xCF, 0x77, 0xB6, 0xD7, 0x5D, 0xFF, 0x35,
            0x3C, 0x35, 0x70, 0x78, 0x03, 0xED, 0x6E, 0x0A, 0x03, 0x65, 0xDC, 0xA4, 0xAA, 0x59, 0x8B, 0xDB
        };

        public static byte[] ImportSecretKey => new byte[]
        {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
        };

        public static byte[] CryptoProKeyMeshingConstant => new byte[]
        {
            0x69, 0x00, 0x72, 0x22, 0x64, 0xC9, 0x04, 0x23,
            0x8D, 0x3A, 0xDB, 0x96, 0x46, 0xE9, 0x2A, 0xC4,
            0x18, 0xFE, 0xAC, 0x94, 0x00, 0xED, 0x07, 0x12,
            0xC0, 0x86, 0xDC, 0xC2, 0xEF, 0x4C, 0xA9, 0x2B
        };

        public static byte[] Digest_Gost3411_SourceData => new byte[]
        {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
        };

        public static byte[] Encrypt_Gost28147_89_ECB_SourceData => new byte[]
        {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
            0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00
        };

        public static byte[] Encrypt_Gost28147_89_CBC_SourceData => new byte[]
        {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
            0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00,
            0xfa, 0xfb
        };

        public static byte[] Encrypt_Gost28147_89_SourceData => new byte[]
        {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
            0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
            0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
            0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
            0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09
        };

        public static byte[] Encrypt_RSA_SourceData => new byte[]
        {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06
        };

        public static string PINPad_Sign_SourceData =>
            "<!PINPADFILE INVISIBLE UTF8><N>ФИО:<V>Петров Петр Петрович Москва, Пионерская ул, д. 3, кв. 72\n" +
            "<N>Перевод со счета:<V>42301810001000075212<N>Сумма:<V>150000<N>Валюта:<V>RUR\n" +
            "<N>Наименование получателя:<V>Иванова Елена Ивановна<N>Номер счета получателя:<V>40817810338295201618\n" +
            "<N>БИК банка получателя:<V>044525225<N>Наименование банка получателя:<V>ОАО 'СБЕРБАНК РОССИИ' Г. МОСКВА\n" +
            "<N>Номер счета банка получателя:<V>30101810400000000225<N>Назначение платежа:<V>перевод личных средств\n";

        public static byte[] PINPad_Certificate_Request1 => new byte[] {
            0x30, 0x82, 0x02, 0x69, 0x02, 0x01, 0x00, 0x30, 0x82, 0x01, 0x83, 0x31, 0x0b, 0x30, 0x09, 0x06,
	        0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x52, 0x55, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04,
	        0x08, 0x13, 0x06, 0x4d, 0x6f, 0x73, 0x63, 0x6f, 0x77, 0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55,
	        0x04, 0x07, 0x13, 0x03, 0x6d, 0x73, 0x6b, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x09,
	        0x13, 0x06, 0x73, 0x74, 0x72, 0x65, 0x65, 0x74, 0x31, 0x0e, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x04,
	        0x0a, 0x13, 0x05, 0x41, 0x6b, 0x74, 0x69, 0x76, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04,
	        0x0b, 0x13, 0x02, 0x49, 0x54, 0x31, 0x17, 0x30, 0x15, 0x06, 0x03, 0x55, 0x04, 0x10, 0x13, 0x0e,
	        0x70, 0x6f, 0x73, 0x74, 0x61, 0x6c, 0x20, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x31, 0x1b,
	        0x30, 0x19, 0x06, 0x03, 0x55, 0x04, 0x0c, 0x1e, 0x12, 0x04, 0x34, 0x04, 0x3e, 0x04, 0x3b, 0x04,
	        0x36, 0x04, 0x3d, 0x04, 0x3e, 0x04, 0x41, 0x04, 0x42, 0x04, 0x4c, 0x31, 0x19, 0x30, 0x17, 0x06,
	        0x08, 0x2a, 0x85, 0x03, 0x03, 0x81, 0x03, 0x01, 0x01, 0x12, 0x0b, 0x31, 0x32, 0x33, 0x34, 0x35,
	        0x36, 0x37, 0x38, 0x39, 0x38, 0x37, 0x31, 0x16, 0x30, 0x14, 0x06, 0x05, 0x2a, 0x85, 0x03, 0x64,
	        0x03, 0x12, 0x0b, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x38, 0x37, 0x31, 0x16,
	        0x30, 0x14, 0x06, 0x05, 0x2a, 0x85, 0x03, 0x64, 0x01, 0x12, 0x0b, 0x31, 0x32, 0x33, 0x34, 0x35,
	        0x36, 0x37, 0x38, 0x39, 0x38, 0x37, 0x31, 0x16, 0x30, 0x14, 0x06, 0x05, 0x2a, 0x85, 0x03, 0x64,
	        0x05, 0x12, 0x0b, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x38, 0x37, 0x31, 0x2f,
	        0x30, 0x2d, 0x06, 0x03, 0x55, 0x04, 0x03, 0x1e, 0x26, 0x04, 0x24, 0x04, 0x30, 0x04, 0x3c, 0x04,
	        0x38, 0x04, 0x3b, 0x04, 0x38, 0x04, 0x4f, 0x00, 0x20, 0x04, 0x18, 0x04, 0x3c, 0x04, 0x4f, 0x00,
	        0x20, 0x04, 0x1e, 0x04, 0x47, 0x04, 0x35, 0x04, 0x41, 0x04, 0x42, 0x04, 0x32, 0x04, 0x3e, 0x31,
	        0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x41, 0x13, 0x09, 0x70, 0x73, 0x65, 0x75, 0x64, 0x6f,
	        0x6e, 0x79, 0x6d, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x04, 0x13, 0x07, 0x73, 0x75,
	        0x72, 0x6e, 0x61, 0x6d, 0x65, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x2a, 0x13, 0x0a,
	        0x67, 0x69, 0x76, 0x65, 0x6e, 0x20, 0x6e, 0x61, 0x6d, 0x65, 0x31, 0x22, 0x30, 0x20, 0x06, 0x09,
	        0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01, 0x16, 0x13, 0x65, 0x78, 0x61, 0x6d, 0x70,
	        0x6c, 0x65, 0x40, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x63,
	        0x30, 0x1c, 0x06, 0x06, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x13, 0x30, 0x12, 0x06, 0x07, 0x2a, 0x85,
	        0x03, 0x02, 0x02, 0x23, 0x01, 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x1e, 0x01, 0x03, 0x43,
	        0x00, 0x04, 0x40, 0x26, 0x68, 0x22, 0x87, 0x6b, 0x3e, 0x60, 0xde, 0x6e, 0xcf, 0x7d, 0x9b, 0xc5,
	        0x99, 0x49, 0x88, 0xe3, 0xce, 0x8d, 0x05, 0xb2, 0x0a, 0x3c, 0x3d, 0x2c, 0xb3, 0x7c, 0xc6, 0x9e,
	        0x7e, 0x5a, 0xc6, 0x95, 0xde, 0x97, 0x86, 0x9a, 0x56, 0xe3, 0xc5, 0xf5, 0xc5, 0xca, 0x9a, 0x4a,
	        0xd9, 0x11, 0xa0, 0x40, 0x08, 0xca, 0x70, 0x29, 0x13, 0x64, 0x7f, 0xa1, 0x6c, 0x5b, 0x5b, 0x25,
	        0xc9, 0xa6, 0x0c, 0xa0, 0x78, 0x30, 0x76, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
	        0x09, 0x0e, 0x31, 0x69, 0x30, 0x67, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x04, 0x04, 0x03,
	        0x02, 0x06, 0xc0, 0x30, 0x16, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x01, 0x01, 0xff, 0x04, 0x0c, 0x30,
	        0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x04, 0x30, 0x13, 0x06, 0x03, 0x55,
	        0x1d, 0x20, 0x04, 0x0c, 0x30, 0x0a, 0x30, 0x08, 0x06, 0x06, 0x2a, 0x85, 0x03, 0x64, 0x71, 0x01,
	        0x30, 0x2b, 0x06, 0x05, 0x2a, 0x85, 0x03, 0x64, 0x6f, 0x04, 0x22, 0x0c, 0x20, 0xd0, 0xa1, 0xd0,
	        0x9a, 0xd0, 0x97, 0xd0, 0x98, 0x20, 0x22, 0xd0, 0xa0, 0xd0, 0xa3, 0xd0, 0xa2, 0xd0, 0x9e, 0xd0,
	        0x9a, 0xd0, 0x95, 0xd0, 0x9d, 0x20, 0xd0, 0xad, 0xd0, 0xa6, 0xd0, 0x9f, 0x22};

        public static byte[] PINPad_Certificate_Request2 => new byte[]
        {
            0x30, 0x82, 0x02, 0x26, 0x02, 0x01, 0x00, 0x30, 0x0f, 0x31, 0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55,
            0x04, 0x03, 0x0c, 0x04, 0x32, 0x30, 0x31, 0x32, 0x30, 0x81, 0xaa, 0x30, 0x21, 0x06, 0x08, 0x2a,
            0x85, 0x03, 0x07, 0x01, 0x01, 0x01, 0x02, 0x30, 0x15, 0x06, 0x09, 0x2a, 0x85, 0x03, 0x07, 0x01,
            0x02, 0x01, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x02, 0x03, 0x03, 0x81,
            0x84, 0x00, 0x04, 0x81, 0x80, 0x2b, 0x3d, 0xa5, 0xfb, 0xb0, 0x7f, 0x43, 0xf5, 0x75, 0x94, 0xaa,
            0x93, 0x26, 0x03, 0x69, 0xe6, 0xe4, 0xea, 0xd5, 0x23, 0x39, 0xc1, 0x03, 0xcd, 0xab, 0x5f, 0xba,
            0x5d, 0xb5, 0x1e, 0x69, 0xc5, 0xfc, 0xe8, 0xac, 0xf2, 0x47, 0xc4, 0x93, 0x96, 0x09, 0x03, 0xc9,
            0xca, 0x4d, 0x8f, 0xaa, 0xfd, 0xea, 0x37, 0x82, 0xdf, 0xb7, 0x87, 0xf3, 0x0f, 0xb8, 0x5f, 0x3c,
            0x65, 0x59, 0x7c, 0x59, 0xe7, 0x47, 0x2b, 0xff, 0xe8, 0x12, 0x04, 0xd9, 0xf9, 0x3d, 0x82, 0xa0,
            0x68, 0x62, 0xee, 0x8e, 0xaa, 0x5a, 0x9e, 0xba, 0x26, 0x3c, 0xe2, 0x49, 0x5e, 0x7d, 0x5c, 0x2f,
            0xe5, 0xc7, 0x7d, 0x8b, 0x92, 0xf2, 0x18, 0x80, 0xb8, 0x18, 0x9e, 0xd1, 0xce, 0x96, 0x4a, 0x71,
            0x36, 0xf6, 0xfb, 0xb1, 0xde, 0xd0, 0xa1, 0xd8, 0x07, 0x1c, 0x2b, 0xc9, 0x4e, 0xbd, 0x40, 0x52,
            0x84, 0x5b, 0x62, 0x0b, 0xdf, 0xa0, 0x82, 0x01, 0x61, 0x30, 0x1a, 0x06, 0x0a, 0x2b, 0x06, 0x01,
            0x04, 0x01, 0x82, 0x37, 0x0d, 0x02, 0x03, 0x31, 0x0c, 0x16, 0x0a, 0x36, 0x2e, 0x31, 0x2e, 0x37,
            0x36, 0x30, 0x31, 0x2e, 0x32, 0x30, 0x4c, 0x06, 0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37,
            0x15, 0x14, 0x31, 0x3f, 0x30, 0x3d, 0x02, 0x01, 0x05, 0x0c, 0x0f, 0x57, 0x49, 0x4e, 0x2d, 0x42,
            0x43, 0x51, 0x35, 0x4e, 0x52, 0x49, 0x4a, 0x35, 0x30, 0x46, 0x0c, 0x13, 0x57, 0x49, 0x4e, 0x2d,
            0x42, 0x43, 0x51, 0x35, 0x4e, 0x52, 0x49, 0x4a, 0x35, 0x30, 0x46, 0x5c, 0x72, 0x65, 0x78, 0x0c,
            0x12, 0x43, 0x65, 0x72, 0x74, 0x45, 0x6e, 0x72, 0x6f, 0x6c, 0x6c, 0x43, 0x74, 0x72, 0x6c, 0x2e,
            0x65, 0x78, 0x65, 0x30, 0x53, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0e,
            0x31, 0x46, 0x30, 0x44, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04,
            0x03, 0x02, 0x04, 0xf0, 0x30, 0x13, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x04, 0x0c, 0x30, 0x0a, 0x06,
            0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e,
            0x04, 0x16, 0x04, 0x14, 0x8f, 0x2c, 0x88, 0x58, 0x36, 0xf3, 0xc9, 0x30, 0xf5, 0x73, 0x84, 0xcc,
            0x34, 0x23, 0x89, 0xda, 0x5f, 0xb8, 0x03, 0xd8, 0x30, 0x81, 0x9f, 0x06, 0x0a, 0x2b, 0x06, 0x01,
            0x04, 0x01, 0x82, 0x37, 0x0d, 0x02, 0x02, 0x31, 0x81, 0x90, 0x30, 0x81, 0x8d, 0x02, 0x01, 0x01,
            0x1e, 0x81, 0x84, 0x00, 0x43, 0x00, 0x72, 0x00, 0x79, 0x00, 0x70, 0x00, 0x74, 0x00, 0x6f, 0x00,
            0x2d, 0x00, 0x50, 0x00, 0x72, 0x00, 0x6f, 0x00, 0x20, 0x00, 0x47, 0x00, 0x4f, 0x00, 0x53, 0x00,
            0x54, 0x00, 0x20, 0x00, 0x52, 0x00, 0x20, 0x00, 0x33, 0x00, 0x34, 0x00, 0x2e, 0x00, 0x31, 0x00,
            0x30, 0x00, 0x2d, 0x00, 0x32, 0x00, 0x30, 0x00, 0x31, 0x00, 0x32, 0x00, 0x20, 0x00, 0x53, 0x00,
            0x74, 0x00, 0x72, 0x00, 0x6f, 0x00, 0x6e, 0x00, 0x67, 0x00, 0x20, 0x00, 0x43, 0x00, 0x72, 0x00,
            0x79, 0x00, 0x70, 0x00, 0x74, 0x00, 0x6f, 0x00, 0x67, 0x00, 0x72, 0x00, 0x61, 0x00, 0x70, 0x00,
            0x68, 0x00, 0x69, 0x00, 0x63, 0x00, 0x20, 0x00, 0x53, 0x00, 0x65, 0x00, 0x72, 0x00, 0x76, 0x00,
            0x69, 0x00, 0x63, 0x00, 0x65, 0x00, 0x20, 0x00, 0x50, 0x00, 0x72, 0x00, 0x6f, 0x00, 0x76, 0x00,
            0x69, 0x00, 0x64, 0x00, 0x65, 0x00, 0x72, 0x03, 0x01, 0x00
        };

        public static byte[] PINPad_AttrData1 => new byte[]
        {
            0x31, 0x69, 0x30, 0x18, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03, 0x31,
            0x0b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01, 0x30, 0x1c, 0x06, 0x09,
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x05, 0x31, 0x0f, 0x17, 0x0d, 0x31, 0x35, 0x30,
            0x33, 0x30, 0x36, 0x31, 0x34, 0x35, 0x39, 0x35, 0x36, 0x5a, 0x30, 0x2f, 0x06, 0x09, 0x2a, 0x86,
            0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04, 0x31, 0x22, 0x04, 0x20,

            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // HASH (pbtDataAttr + 75)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };

        public static byte[] PINPad_AttrData2 => new byte[]
        {
            0x31, 0x82, 0x01, 0x1a, 0x30, 0x18, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09,
            0x03, 0x31, 0x0b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01, 0x30, 0x1c,
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x05, 0x31, 0x0f, 0x17, 0x0d, 0x31,
            0x31, 0x31, 0x32, 0x31, 0x39, 0x31, 0x34, 0x30, 0x30, 0x30, 0x32, 0x5a, 0x30, 0x4f, 0x06, 0x09,
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04, 0x31, 0x42, 0x04, 0x40,

            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // HASH (pbtDataAttr + 77)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

            0x30, 0x81, 0x8e, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0f, 0x31, 0x81,
            0x80, 0x30, 0x7e, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2a,
            0x30, 0x08, 0x06, 0x06, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x09, 0x30, 0x08, 0x06, 0x06, 0x2a, 0x85,
            0x03, 0x02, 0x02, 0x15, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01,
            0x16, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x02, 0x30, 0x0a,
            0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x03, 0x07, 0x30, 0x0e, 0x06, 0x08, 0x2a, 0x86,
            0x48, 0x86, 0xf7, 0x0d, 0x03, 0x02, 0x02, 0x02, 0x00, 0x80, 0x30, 0x0d, 0x06, 0x08, 0x2a, 0x86,
            0x48, 0x86, 0xf7, 0x0d, 0x03, 0x02, 0x02, 0x01, 0x40, 0x30, 0x07, 0x06, 0x05, 0x2b, 0x0e, 0x03,
            0x02, 0x07, 0x30, 0x0d, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x03, 0x02, 0x02, 0x01,
            0x28
        };

        public static string PKCS7_SignData => "01234";

        public static byte[] PKCS7_SignDataBytes => new byte[]
        {
            0x01, 0x00, 0x02, 0x35, 0x35,
            0x02, 0x00, 0x01, 0x01,
            0x81, 0x00, 0x09, 0x34, 0x30, 0x34, 0x34, 0x34, 0x35, 0x39, 0x39, 0x38,
            0x82, 0x00, 0x0A, 0x37, 0x37, 0x38, 0x31, 0x35, 0x36, 0x34, 0x36, 0x31, 0x31,
            0x83, 0x00, 0x13, 0x41, 0x6B, 0x74, 0x69, 0x76, 0x20, 0x52, 0x75, 0x74, 0x6F, 0x6B, 0x65, 0x6E, 0x20, 0x42,
            0x61, 0x6E, 0x6B, 0x2E,
            0x84, 0x00, 0x14, 0x34, 0x37, 0x37, 0x37, 0x38, 0x38, 0x38, 0x39, 0x39, 0x39, 0x31, 0x31, 0x31, 0x31, 0x31,
            0x32, 0x32, 0x32, 0x37, 0x36,
            0x85, 0x00, 0x0A, 0x33, 0x32, 0x32, 0x38, 0x37, 0x33, 0x36, 0x37, 0x36, 0x35,
            0x86, 0x00, 0x03, 0x52, 0x55, 0x42,
            0xFF, 0x00, 0x0D, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30
        };
    }
}
