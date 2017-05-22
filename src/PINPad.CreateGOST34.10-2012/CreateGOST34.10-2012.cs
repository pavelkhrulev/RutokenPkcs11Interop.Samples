using System;
using System.Collections.Generic;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using RutokenPkcs11Interop;
using RutokenPkcs11Interop.Common;
using RutokenPkcs11Interop.HighLevelAPI;
using RutokenPkcs11Interop.Samples.Common;

namespace PINPad.CreateGOST3410_2012
{
    /*************************************************************************
    * Rutoken                                                                *
    * Copyright (c) 2003-2017, CJSC Aktiv-Soft. All rights reserved.         *
    * Подробная информация:  http://www.rutoken.ru                           *
    *------------------------------------------------------------------------*
    * Пример работы с Рутокен PINPad при помощи библиотеки PKCS#11           *
    * на языке C#                                                            *
    *------------------------------------------------------------------------*
    * Использование команд создания объектов в памяти Рутокен PINPad:        *
    *  - установление соединения с Рутокен PINPad в первом доступном слоте;  *
    *  - определение модели подключенного устройства;                        *
    *  - выполнение аутентификации Пользователя;                             *
    *  - создание ключевой пары ГОСТ Р 34.10-2012(512) с атрибутами          *
    *    подтверждения подписи данных и вводом PIN-кода на экране PINPad;    *
    *  - сброс прав доступа Пользователя на Рутокен PINPad и закрытие        *
    *    соединения с Рутокен PINPad.                                        *
    *------------------------------------------------------------------------*
    * Созданные примером объекты используются также и в других примерах      *
    * работы с библиотекой PKCS#11.                                          *
    *************************************************************************/

    class CreateGOST3410_2012
    {
        // Шаблон для создания открытого ключа ГОСТ Р 34.10-2012(512)
        static readonly List<ObjectAttribute> PublicKeyAttributes = new List<ObjectAttribute>()
        {
            new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY), // Объект открытого ключа
            new ObjectAttribute(CKA.CKA_LABEL, SampleConstants.Gost512PublicKeyLabel1),  // Метка ключа
            new ObjectAttribute(CKA.CKA_ID, SampleConstants.Gost512KeyPairId1), // Идентификатор ключевой пары (должен совпадать у открытого и закрытого ключей)
            new ObjectAttribute(CKA.CKA_KEY_TYPE, (uint)Extended_CKK.CKK_GOSTR3410_512), // Тип ключа ГОСТ Р 34.10-2012
            new ObjectAttribute(CKA.CKA_TOKEN, true),  // Ключ является объектом токена
            new ObjectAttribute(CKA.CKA_PRIVATE, false), // Ключ доступен без аутентификации
            new ObjectAttribute((uint) Extended_CKA.CKA_GOSTR3410_PARAMS, SampleConstants.GostR3410_512_Parameters), // Параметры алгоритма ГОСТ Р 34.10-2012
            new ObjectAttribute((uint) Extended_CKA.CKA_GOSTR3411_PARAMS, SampleConstants.GostR3411_512_Parameters) // Параметры алгоритма ГОСТ Р 34.11-2012
        };

        // Шаблон для создания закрытого ключа ГОСТ Р 34.10-2012(512)
        static readonly List<ObjectAttribute> PrivateKeyAttributes = new List<ObjectAttribute>()
        {
            new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY), // Объект закрытого ключа
            new ObjectAttribute(CKA.CKA_LABEL, SampleConstants.Gost512PrivateKeyLabel1), // Метка ключа
            new ObjectAttribute(CKA.CKA_ID, SampleConstants.Gost512KeyPairId1), // Идентификатор ключевой пары (должен совпадать у открытого и закрытого ключей)
            new ObjectAttribute(CKA.CKA_KEY_TYPE, (uint)Extended_CKK.CKK_GOSTR3410_512), // Тип ключа ГОСТ Р 34.10-2012
            new ObjectAttribute(CKA.CKA_TOKEN, true), // Ключ является объектом токена
            new ObjectAttribute(CKA.CKA_PRIVATE, true), // Ключ доступен только после аутентификации
            new ObjectAttribute((uint) Extended_CKA.CKA_VENDOR_KEY_CONFIRM_OP, true), // Операция подписи требует подтверждения на PINPad
            new ObjectAttribute((uint) Extended_CKA.CKA_VENDOR_KEY_PIN_ENTER, true), // Операция подписи требует ввода PIN-кода на PINPad
            new ObjectAttribute((uint) Extended_CKA.CKA_GOSTR3410_PARAMS, SampleConstants.GostR3410_512_Parameters), // Параметры алгоритма ГОСТ Р 34.10-2012
            new ObjectAttribute((uint) Extended_CKA.CKA_GOSTR3411_PARAMS, SampleConstants.GostR3411_512_Parameters) // Параметры алгоритма ГОСТ Р 34.11-2012
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
                    bool isGostR3410_512Supported = mechanisms.Contains((CKM)Extended_CKM.CKM_GOSTR3410_512_KEY_PAIR_GEN);
                    Errors.Check("CKM_GOSTR3410_512_KEY_PAIR_GEN isn`t supported!", isGostR3410_512Supported);

                    // Открыть RW сессию в первом доступном слоте
                    Console.WriteLine("Opening RW session");
                    using (Session session = slot.OpenSession(false))
                    {
                        // Выполнить аутентификацию Пользователя
                        Console.WriteLine("User authentication");
                        session.Login(CKU.CKU_USER, SampleConstants.NormalUserPin);

                        // Определить механизм генерации ключа
                        Console.WriteLine("Generating GOST R 34.10-2012 key pair...");
                        var mechanism = new Mechanism((uint)Extended_CKM.CKM_GOSTR3410_512_KEY_PAIR_GEN);

                        // Сгенерировать первую ключевую пару ГОСТ Р 34.10-2001
                        ObjectHandle publicKeyHandle;
                        ObjectHandle privateKeyHandle;
                        session.GenerateKeyPair(mechanism, PublicKeyAttributes, PrivateKeyAttributes, out publicKeyHandle, out privateKeyHandle);
                        Errors.Check("Invalid public key handle", publicKeyHandle.ObjectId != CK.CK_INVALID_HANDLE);
                        Errors.Check("Invalid private key handle", privateKeyHandle.ObjectId != CK.CK_INVALID_HANDLE);

                        Console.WriteLine("Generating has been completed successfully");

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
