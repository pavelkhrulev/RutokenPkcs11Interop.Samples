﻿using System;
using System.Collections.Generic;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using RutokenPkcs11Interop;
using RutokenPkcs11Interop.Common;
using RutokenPkcs11Interop.HighLevelAPI;
using RutokenPkcs11Interop.Samples.Common;

namespace PINPad.SignAttrGOST3410_2001
{
    /*************************************************************************
    * Rutoken                                                                *
    * Copyright (c) 2003-2017, CJSC Aktiv-Soft. All rights reserved.         *
    * Подробная информация:  http://www.rutoken.ru                           *
    *------------------------------------------------------------------------*
    * Пример работы с Рутокен PINPad при помощи библиотеки PKCS#11           *
    * на языке C#                                                            *
    *------------------------------------------------------------------------*
    * Использование команд вычисления/проверки ЭП на ключах ГОСТ 34.10-2001: *
    *  - установление соединения с Рутокен PINPad в первом доступном слоте;  *
    *  - выполнение аутентификации Пользователя;                             *
    *  - подпись отображаемых платежных данных с атрибутами на экране PINPad;*
    *  - проверка подписи;                                                   *
    *  - сброс прав доступа Пользователя на Рутокен PINPad и закрытие        *
    *    соединения с Рутокен PINPad.                                        *
    *------------------------------------------------------------------------*
    * Пример использует объекты, созданные в памяти Рутокен PINPad примером  *
    * CreateGOST34.10-2001-PINPad.                                           *
    *************************************************************************/

    class SignAttrGOST3410_2001
    {
        // Шаблон для поиска открытого ключа ГОСТ Р 34.10-2001
        static readonly List<ObjectAttribute> PublicKeyAttributes = new List<ObjectAttribute>()
        {
            new ObjectAttribute(CKA.CKA_ID, SampleConstants.GostKeyPairId1), // ID пары
            new ObjectAttribute(CKA.CKA_KEY_TYPE, (uint)Extended_CKK.CKK_GOSTR3410), // Ключ ГОСТ Р 34.10-2001
            new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY) // Класс - открытый ключ
        };

        // Шаблон для поиска закрытого ключа ГОСТ Р 34.10-2001
        static readonly List<ObjectAttribute> PrivateKeyAttributes = new List<ObjectAttribute>()
        {
            new ObjectAttribute(CKA.CKA_ID, SampleConstants.GostKeyPairId1), // ID пары
            new ObjectAttribute(CKA.CKA_KEY_TYPE, (uint)Extended_CKK.CKK_GOSTR3410), // Ключ ГОСТ Р 34.10-2001
            new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY) // Класс - закрытый ключ
        };

        static void Main(string[] args)
        {
            try
            {
                // Инициализировать библиотеку
                Console.WriteLine("Library initialization");
                using (var pkcs11 = new Pkcs11(Settings.RutokenEcpDllDefaultPath, Settings.OsLockingDefault))
                {
                    // Получить доступный слот
                    Console.WriteLine("Checking tokens available");
                    Slot slot = Helpers.GetUsableSlot(pkcs11);

                    // Получить расширенную информацию о подключенном токене
                    Console.WriteLine("Checking token type");
                    TokenInfoExtended tokenInfo = slot.GetTokenInfoExtended();
                    // Проверить наличие PINPad в нулевом слоте
                    Errors.Check("Device in slot 0 is not Rutoken PINPad", tokenInfo.TokenType == RutokenType.PINPAD_FAMILY);

                    // Определение поддерживаемых токеном механизмов
                    Console.WriteLine("Checking mechanisms available");
                    List<CKM> mechanisms = slot.GetMechanismList();
                    Errors.Check("No mechanisms available", mechanisms.Count > 0);
                    bool isGostR3410Supported = mechanisms.Contains((CKM)Extended_CKM.CKM_GOSTR3410);
                    bool isGostR3411Supported = mechanisms.Contains((CKM)Extended_CKM.CKM_GOSTR3411);
                    Errors.Check("CKM_GOSTR3410 isn`t supported!", isGostR3410Supported);
                    Errors.Check("CKM_GOSTR3411 isn`t supported!", isGostR3411Supported);

                    // Открыть RW сессию в первом доступном слоте
                    Console.WriteLine("Opening RW session");
                    using (Session session = slot.OpenSession(false))
                    {
                        // Выполнить аутентификацию Пользователя
                        Console.WriteLine("User authentication");
                        session.Login(CKU.CKU_USER, SampleConstants.NormalUserPin);

                        // Получить данные для вычисления подписи
                        string sourceData = SampleData.PINPad_Sign_SourceData;

                        // Получить приватный ключ для генерации подписи
                        Console.WriteLine("Getting private key...");
                        List<ObjectHandle> privateKeys = session.FindAllObjects(PrivateKeyAttributes);
                        Errors.Check("No private keys found", privateKeys.Count > 0);

                        // Инициализировать операцию хэширования
                        var mechanism = new Mechanism((uint)Extended_CKM.CKM_GOSTR3411);

                        // Вычислить хэш-код данных
                        Console.WriteLine("Hashing data without attributes...");
                        byte[] hash = session.Digest(mechanism, ConvertUtils.Utf8StringToBytes(sourceData));

                        // Распечатать буфер, содержащий хэш-код
                        Console.WriteLine(" Hashed buffer is:");
                        Helpers.PrintByteArray(hash);
                        Console.WriteLine("Hashing has been completed successfully");

                        // Вычислить хэш-код данных
                        Console.WriteLine("Hashing data with attributes...");
                        byte[] attrData = SampleData.PINPad_AttrData1;
                        var hashOffset = 75;
                        Buffer.BlockCopy(hash, 0, attrData, hashOffset, hash.Length);
                        byte[] attrHash = session.Digest(mechanism, attrData);

                        // Распечатать буфер, содержащий хэш-код
                        Console.WriteLine(" Hashed buffer is:");
                        Helpers.PrintByteArray(attrHash);
                        Console.WriteLine("Hashing has been completed successfully");

                        // Получить значение флага подтверждения операции подписи
                        Console.WriteLine("Checking whether signature confirmation is required...");
                        var attributes = new List<CKA>
                        {
                            (CKA)Extended_CKA.CKA_VENDOR_KEY_CONFIRM_OP
                        };
                        List<ObjectAttribute> confirm = session.GetAttributeValue(privateKeys[0], attributes);

                        /*************************************************************************
                        * Инициализировать операцию подписи данных                               *
                        *************************************************************************/
                        /*************************************************************************
                        * При подписи сообщения с заголовком <!PINPADFILE INVISIBLE RU> или      *
                        * <!PINPADFILE INVISIBLE UTF8> на ключе, имеющем атрибут                 *
                        * CKA_VENDOR_KEY_CONFIRM_OP равным CK_TRUE, а так же для подписи на      *
                        * ключе, имеющем атрибут CKA_VENDOR_KEY_CONFIRM_OP равным CK_FALSE, для  *
                        * инициализации подписи должна использоваться функция                    *
                        * C_EX_SignInvisibleInit, для подписи - C_EX_SignInvisible.              *
                        *                                                                        *
                        * При подписи сообщения с заголовком <!PINPADFILE RU> или                *
                        * <!PINPADFILE UTF8> на ключе, имеющем атрибут CKA_VENDOR_KEY_CONFIRM_OP *
                        * равным CK_TRUE, для инициализации подписи должна использоваться        *
                        * функция C_SignInit, для подписи - C_Sign.                              *
                        *************************************************************************/
                        bool isOperationInvisible = (sourceData.StartsWith("<!PINPADFILE INVISIBLE RU>") ||
                                                     sourceData.StartsWith("<!PINPADFILE INVISIBLE UTF8>") &&
                                                     confirm[0].GetValueAsBool()) ||
                                                     confirm[0].GetValueAsBool() == false;

                        // Инициализация операции подписи данных по алгоритму ГОСТ Р 34.10-2001
                        var signMechanism = new Mechanism((uint)Extended_CKM.CKM_GOSTR3410);

                        // Подписать данные
                        byte[] signature;
                        if (isOperationInvisible)
                        {
                            Console.WriteLine("Signing data invisible...");
                            signature = session.SignInvisible(signMechanism, privateKeys[0], attrHash);
                        }
                        else
                        {
                            Console.WriteLine("Signing data...");
                            signature = session.Sign(signMechanism, privateKeys[0], attrHash);
                        }

                        // Распечатать буфер, содержащий подпись
                        Console.WriteLine(" Signature buffer is:");
                        Helpers.PrintByteArray(signature);
                        Console.WriteLine("Data has been signed successfully");

                        // Получить публичный ключ для проверки подписи
                        Console.WriteLine("Getting public key...");
                        List<ObjectHandle> publicKeys = session.FindAllObjects(PublicKeyAttributes);
                        Errors.Check("No public keys found", publicKeys.Count > 0);

                        // Проверка подписи для данных
                        Console.WriteLine("Verifying signature...");
                        bool isSignatureValid = false;
                        session.Verify(signMechanism, publicKeys[0], attrHash, signature, out isSignatureValid);

                        if (isSignatureValid)
                            Console.WriteLine("Verifying has been completed successfully");
                        else
                            throw new InvalidOperationException("Invalid signature");

                        // Сбросить права доступа
                        session.Logout();
                    }
                }
            }
            catch (Pkcs11Exception ex)
            {
                Console.WriteLine($"Operation failed [Method: {ex.Method}, RV: {ex.RV}]");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Operation failed [Message: {ex.Message}]");
            }
        }
    }
}