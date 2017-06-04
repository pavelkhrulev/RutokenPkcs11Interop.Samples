using System;
using System.Collections.Generic;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using RutokenPkcs11Interop;
using RutokenPkcs11Interop.Common;
using RutokenPkcs11Interop.HighLevelAPI;
using RutokenPkcs11Interop.Samples.Common;

namespace PKIExtensions.CreateCSR_PKCS10
{
    /*************************************************************************
    * Rutoken                                                                *
    * Copyright (c) 2003-2017, CJSC Aktiv-Soft. All rights reserved.         *
    * Подробная информация:  http://www.rutoken.ru                           *
    *------------------------------------------------------------------------*
    * Пример работы с Рутокен ЭЦП при помощи библиотеки PKCS#11 на языке C#  *
    *------------------------------------------------------------------------*
    * Использование команды создания запроса на сертификат ключа подписи для *
    * ключевой пары ГОСТ 34.10-2001:                                         *
    *  - установление соединения с Рутокен ЭЦП в первом доступном слоте;     *
    *  - выполнение аутентификации Пользователя;                             *
    *  - генерация ключевой пары ГОСТ 34.10-2001 на Рутокен;                 *
    *  - создание подписанного запроса на сертификат для сгенерированной     *
    *    ключевой пары и его вывод;                                          *
    *  - сброс прав доступа Пользователя и закрытие соединения с Рутокен.    *
    *------------------------------------------------------------------------*
    * Созданные примером объекты используются также и в других примерах      *
    * работы с библиотекой PKCS#11.                                          *
    *************************************************************************/

    class CreateCSR_PKCS10
    {
        // Шаблон для создания открытого ключа ГОСТ Р 34.10-2001
        static readonly List<ObjectAttribute> PublicKeyAttributes = new List<ObjectAttribute>
        {
            // Объект открытого ключа
            new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY),
            // Метка ключа
            new ObjectAttribute(CKA.CKA_LABEL, SampleConstants.GostPublicKeyLabel1),
            // Идентификатор ключевой пары #1 (должен совпадать у открытого и закрытого ключей)
            new ObjectAttribute(CKA.CKA_ID, SampleConstants.GostKeyPairId1),
            // Тип ключа - ГОСТ Р 34.10-2001
            new ObjectAttribute(CKA.CKA_KEY_TYPE, (uint) Extended_CKK.CKK_GOSTR3410),
            // Открытый ключ является объектом токена
            new ObjectAttribute(CKA.CKA_TOKEN, true),
            // Ключ доступен без аутентификации
            new ObjectAttribute(CKA.CKA_PRIVATE, false),
            // Параметры алгоритма ГОСТ Р 34.10-2001
            new ObjectAttribute((uint) Extended_CKA.CKA_GOSTR3410_PARAMS, SampleConstants.GostR3410Parameters)
        };

        // Шаблон для создания закрытого ключа ГОСТ Р 34.10-2001
        static readonly List<ObjectAttribute> PrivateKeyAttributes = new List<ObjectAttribute>
        {
            // Объект закрытого ключа
            new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
            // Метка ключа
            new ObjectAttribute(CKA.CKA_LABEL, SampleConstants.GostPrivateKeyLabel1),
            // Идентификатор ключевой пары #1 (должен совпадать у открытого и закрытого ключей)
            new ObjectAttribute(CKA.CKA_ID, SampleConstants.GostKeyPairId1),
            // Тип ключа - ГОСТ Р 34.10-2001
            new ObjectAttribute(CKA.CKA_KEY_TYPE, (uint) Extended_CKK.CKK_GOSTR3410),
            // Открытый ключ является объектом токена
            new ObjectAttribute(CKA.CKA_TOKEN, true),
            // Ключ доступен без аутентификации
            new ObjectAttribute(CKA.CKA_PRIVATE, true),
            // Ключ поддерживает выработку общих ключей (VKO)
            new ObjectAttribute(CKA.CKA_DERIVE, true),
            // Параметры алгоритма ГОСТ Р 34.10-2001
            new ObjectAttribute((uint) Extended_CKA.CKA_GOSTR3410_PARAMS, SampleConstants.GostR3410Parameters)
        };

        // Список полей DN (Distinguished Name)
        static readonly string[] Dn =
        {
            "CN",
            "UTF8String:Иванов",
            "C",
            "RU",
            "2.5.4.5",
            "12312312312",
            "1.2.840.113549.1.9.1",
            "ivanov@mail.ru",
            "ST",
            "UTF8String:Москва"
        };

        // Список дополнительных полей
        static readonly string[] Exts =
        {
            "keyUsage",
            "digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment",
            "extendedKeyUsage",
            "1.2.643.2.2.34.6,1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4",
            "2.5.29.14",
            "ASN1:FORMAT:HEX,OCTETSTRING:FE117B93CEC6B5065E1613E155D3A9CA597C0F81",
            "1.2.643.100.111",
            "ASN1:UTF8String:СКЗИ \\\"Рутокен ЭЦП 2.0\\\""
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

                    // Определение поддерживаемых токеном механизмов
                    Console.WriteLine("Checking mechanisms available");
                    List<CKM> mechanisms = slot.GetMechanismList();
                    Errors.Check(" No mechanisms available", mechanisms.Count > 0);
                    bool isGostR3410Supported = mechanisms.Contains((CKM)Extended_CKM.CKM_GOSTR3410_KEY_PAIR_GEN);
                    Errors.Check(" CKM_GOSTR3410_KEY_PAIR_GEN isn`t supported!", isGostR3410Supported);

                    // Открыть RW сессию в первом доступном слоте
                    Console.WriteLine("Opening RW session");
                    using (Session session = slot.OpenSession(false))
                    {
                        // Выполнить аутентификацию Пользователя
                        Console.WriteLine("User authentication");
                        session.Login(CKU.CKU_USER, SampleConstants.NormalUserPin);

                        try
                        {
                            // Создать запрос на сертификат
                            Console.WriteLine("Creating CSR...");

                            // Генерация ключевой пары на токене
                            // Определить механизм генерации ключа
                            Console.WriteLine("Generating GOST R 34.10-2001 exchange key pairs...");
                            var mechanism = new Mechanism((uint)Extended_CKM.CKM_GOSTR3410_KEY_PAIR_GEN);

                            ObjectHandle publicKeyHandle;
                            ObjectHandle privateKeyHandle;
                            session.GenerateKeyPair(mechanism, PublicKeyAttributes, PrivateKeyAttributes, out publicKeyHandle, out privateKeyHandle);
                            Errors.Check("Invalid public key handle", publicKeyHandle.ObjectId != CK.CK_INVALID_HANDLE);
                            Errors.Check("Invalid private key handle", privateKeyHandle.ObjectId != CK.CK_INVALID_HANDLE);

                            // Создание запроса на сертификат
                            string csr = session.CreateCSR(publicKeyHandle, Dn, privateKeyHandle, null, Exts);
                            Errors.Check("Invalid csr", csr != null);
                            Errors.Check("Invalid csr length", csr.Length > 0);

                            // Распечатать буфер в кодировке Base64
                            Console.WriteLine(csr);
                            Console.WriteLine("Creating has been completed successfully.");
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
