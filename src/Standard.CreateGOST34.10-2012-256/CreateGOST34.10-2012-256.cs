using System;
using System.Collections.Generic;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using RutokenPkcs11Interop;
using RutokenPkcs11Interop.Common;
using RutokenPkcs11Interop.Samples.Common;

namespace Standard.CreateGOST3410_2012_256
{
    /*************************************************************************
    * Rutoken                                                                *
    * Copyright (c) 2003-2019, CJSC Aktiv-Soft. All rights reserved.         *
    * Подробная информация:  http://www.rutoken.ru                           *
    *------------------------------------------------------------------------*
    * Пример работы с Рутокен при помощи библиотеки PKCS#11 на языке C#      *
    *------------------------------------------------------------------------*
    * Использование команд создания объектов в памяти Рутокен:               *
    *  - установление соединения с Рутокен в первом доступном слоте;         *
    *  - выполнение аутентификации Пользователя;                             *
    *  - генерация ключевой пары ГОСТ Р 34.10-2012                           *
    *    с длиной закрытого ключа 256 бит;                                   *
    *  - сброс прав доступа Пользователя на Рутокен и закрытие соединения    *
    *    с Рутокен.                                                          *
    *------------------------------------------------------------------------*
    * Созданные примером объекты используются также и в других примерах      *
    * работы с библиотекой PKCS#11.                                          *
    *************************************************************************/
    class CreateGOST3410_2012_256
    {
        // Шаблон для генерации открытого ключа ГОСТ Р 34.10-2012(256)
        // (первая ключевая пара для подписи и обмена ключами)
        static readonly List<ObjectAttribute> PublicKeyAttributes1 = new List<ObjectAttribute>
        {
            // Класс - открытый ключ
            new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY),
            // Метка ключа
            new ObjectAttribute(CKA.CKA_LABEL, SampleConstants.Gost256PublicKeyLabel1),
            // Идентификатор ключевой пары #1 (должен совпадать у открытого и закрытого ключей)
            new ObjectAttribute(CKA.CKA_ID, SampleConstants.Gost256KeyPairId1),
            // Тип ключа - ГОСТ Р 34.10-2012(256)
            new ObjectAttribute(CKA.CKA_KEY_TYPE, (uint) Extended_CKK.CKK_GOSTR3410),
            // Ключ является объектом токена
            new ObjectAttribute(CKA.CKA_TOKEN, true),
            // Ключ доступен без аутентификации на токене
            new ObjectAttribute(CKA.CKA_PRIVATE, false),
            // Параметры алгоритма ГОСТ Р 34.10-2012
            new ObjectAttribute((uint) Extended_CKA.CKA_GOSTR3410_PARAMS, SampleConstants.GostR3410_256_Parameters),
            // Параметры алгоритма ГОСТ Р 34.11-2012
            new ObjectAttribute((uint) Extended_CKA.CKA_GOSTR3411_PARAMS, SampleConstants.GostR3411_256_Parameters)
        };

        // Шаблон для генерации закрытого ключа ГОСТ Р 34.10-2012(256)
        // (первая ключевая пара для подписи и обмена ключами)
        static readonly List<ObjectAttribute> PrivateKeyAttributes1 = new List<ObjectAttribute>
        {
            // Класс - закрытый ключ
            new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
            // Метка ключа
            new ObjectAttribute(CKA.CKA_LABEL, SampleConstants.Gost256PrivateKeyLabel1),
            // Идентификатор ключевой пары #1 (должен совпадать у открытого и закрытого ключей)
            new ObjectAttribute(CKA.CKA_ID, SampleConstants.Gost256KeyPairId1),
            // Тип ключа - ГОСТ Р 34.10-2012(256)
            new ObjectAttribute(CKA.CKA_KEY_TYPE, (uint) Extended_CKK.CKK_GOSTR3410),
            // Ключ является объектом токена
            new ObjectAttribute(CKA.CKA_TOKEN, true),
            // Ключ доступен только после аутентификации на токене
            new ObjectAttribute(CKA.CKA_PRIVATE, true),
            // Ключ поддерживает выработку общих ключей (VKO)
            new ObjectAttribute(CKA.CKA_DERIVE, true),
            // Параметры алгоритма ГОСТ Р 34.10-2012
            new ObjectAttribute((uint) Extended_CKA.CKA_GOSTR3410_PARAMS, SampleConstants.GostR3410_256_Parameters),
            // Параметры алгоритма ГОСТ Р 34.11-2012
            new ObjectAttribute((uint) Extended_CKA.CKA_GOSTR3411_PARAMS, SampleConstants.GostR3411_256_Parameters)
        };

        // Шаблон для генерации открытого ключа ГОСТ Р 34.10-2012(256)
        // (вторая ключевая пара для подписи и обмена ключами)
        static readonly List<ObjectAttribute> PublicKeyAttributes2 = new List<ObjectAttribute>
        {
            // Класс - открытый ключ
            new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY),
            // Метка ключа
            new ObjectAttribute(CKA.CKA_LABEL, SampleConstants.Gost256PublicKeyLabel2),
            // Идентификатор ключевой пары #2 (должен совпадать у открытого и закрытого ключей)
            new ObjectAttribute(CKA.CKA_ID, SampleConstants.Gost256KeyPairId2),
            // Тип ключа - ГОСТ Р 34.10-2012(256)
            new ObjectAttribute(CKA.CKA_KEY_TYPE, (uint) Extended_CKK.CKK_GOSTR3410),
            // Ключ является объектом токена
            new ObjectAttribute(CKA.CKA_TOKEN, true),
            // Ключ доступен без аутентификации на токене
            new ObjectAttribute(CKA.CKA_PRIVATE, false),
            // Параметры алгоритма ГОСТ Р 34.10-2012
            new ObjectAttribute((uint) Extended_CKA.CKA_GOSTR3410_PARAMS, SampleConstants.GostR3410_256_Parameters),
            // Параметры алгоритма ГОСТ Р 34.11-2012
            new ObjectAttribute((uint) Extended_CKA.CKA_GOSTR3411_PARAMS, SampleConstants.GostR3411_256_Parameters)
        };

        // Шаблон для генерации закрытого ключа ГОСТ Р 34.10-2012(256)
        // (вторая ключевая пара для подписи и обмена ключами)
        static readonly List<ObjectAttribute> PrivateKeyAttributes2 = new List<ObjectAttribute>
        {
            // Класс - закрытый ключ
            new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
            // Метка ключа
            new ObjectAttribute(CKA.CKA_LABEL, SampleConstants.Gost256PrivateKeyLabel2),
            // Идентификатор ключевой пары #2 (должен совпадать у открытого и закрытого ключей)
            new ObjectAttribute(CKA.CKA_ID, SampleConstants.Gost256KeyPairId2),
            // Тип ключа - ГОСТ Р 34.10-2012(256)
            new ObjectAttribute(CKA.CKA_KEY_TYPE, (uint) Extended_CKK.CKK_GOSTR3410),
            // Ключ является объектом токена
            new ObjectAttribute(CKA.CKA_TOKEN, true),
            // Ключ доступен только после аутентификации на токене
            new ObjectAttribute(CKA.CKA_PRIVATE, true),
            // Ключ поддерживает выработку общих ключей (VKO)
            new ObjectAttribute(CKA.CKA_DERIVE, true),
            // Параметры алгоритма ГОСТ Р 34.10-2012
            new ObjectAttribute((uint) Extended_CKA.CKA_GOSTR3410_PARAMS, SampleConstants.GostR3410_256_Parameters),
            // Параметры алгоритма ГОСТ Р 34.11-2012
            new ObjectAttribute((uint) Extended_CKA.CKA_GOSTR3411_PARAMS, SampleConstants.GostR3411_256_Parameters)
        };

        static void Main(string[] args)
        {
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

                        // Определение поддерживаемых токеном механизмов
                        Console.WriteLine("Checking mechanisms available");
                        List<CKM> mechanisms = slot.GetMechanismList();
                        Errors.Check("No mechanisms available", mechanisms.Count > 0);
                        bool isGostR3410_256Supported =
                            mechanisms.Contains((CKM)Extended_CKM.CKM_GOSTR3410_KEY_PAIR_GEN);
                        Errors.Check("CKM_GOSTR3410_KEY_PAIR_GEN isn`t supported!", isGostR3410_256Supported);

                        bool isGostR3411_12_256Supported =
                            mechanisms.Contains((CKM)Extended_CKM.CKM_GOSTR3411_12_256);
                        Errors.Check("CKM_GOSTR3411_12_256 isn`t supported!", isGostR3411_12_256Supported);

                        // Открыть RW сессию в первом доступном слоте
                        Console.WriteLine("Opening RW session");
                        using (Session session = slot.OpenSession(false))
                        {
                            // Выполнить аутентификацию Пользователя
                            Console.WriteLine("User authentication");
                            session.Login(CKU.CKU_USER, SampleConstants.NormalUserPin);

                            try
                            {
                                // Определить механизм генерации ключа
                                Console.WriteLine("Generating GOST R 34.10-2012(256) exchange key pairs...");
                                var mechanism = new Mechanism((uint)Extended_CKM.CKM_GOSTR3410_KEY_PAIR_GEN);

                                // Сгенерировать первую ключевую пару ГОСТ Р 34.10-2012(256)
                                ObjectHandle publicKeyHandle1;
                                ObjectHandle privateKeyHandle1;
                                session.GenerateKeyPair(mechanism, PublicKeyAttributes1, PrivateKeyAttributes1, out publicKeyHandle1, out privateKeyHandle1);
                                Errors.Check("Invalid public key 1 handle", publicKeyHandle1.ObjectId != CK.CK_INVALID_HANDLE);
                                Errors.Check("Invalid private key 1 handle", privateKeyHandle1.ObjectId != CK.CK_INVALID_HANDLE);

                                // Сгенерировать вторую ключевую пару ГОСТ Р 34.10-2012(256)
                                ObjectHandle publicKeyHandle2;
                                ObjectHandle privateKeyHandle2;
                                session.GenerateKeyPair(mechanism, PublicKeyAttributes2, PrivateKeyAttributes2, out publicKeyHandle2, out privateKeyHandle2);
                                Errors.Check("Invalid public key 2 handle", publicKeyHandle2.ObjectId != CK.CK_INVALID_HANDLE);
                                Errors.Check("Invalid private key 2 handle", privateKeyHandle2.ObjectId != CK.CK_INVALID_HANDLE);

                                Console.WriteLine("Generating has been completed successfully");
                            }
                            finally
                            {
                                // Сбросить права доступа как в случае исключения,
                                // так и в случае успеха.
                                // Сессия закрывается автоматически.
                                session.Logout();
                            }
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
}
