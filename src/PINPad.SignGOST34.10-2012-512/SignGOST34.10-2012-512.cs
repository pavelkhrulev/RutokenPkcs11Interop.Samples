using System;
using System.Collections.Generic;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using RutokenPkcs11Interop;
using RutokenPkcs11Interop.Common;
using RutokenPkcs11Interop.HighLevelAPI;
using RutokenPkcs11Interop.Samples.Common;

namespace PINPad.SignGOST3410_2012_512
{
    /*************************************************************************
    * Rutoken                                                                *
    * Copyright (c) 2003-2019, CJSC Aktiv-Soft. All rights reserved.         *
    * Подробная информация:  http://www.rutoken.ru                           *
    *------------------------------------------------------------------------*
    * Пример работы с Рутокен PINPad при помощи библиотеки PKCS#11           *
    * на языке C#                                                            *
    *------------------------------------------------------------------------*
    * Использование команд вычисления/проверки ЭП на ключах                  *
    * ГОСТ Р 34.10-2012 (512):                                               *
    *  - установление соединения с Рутокен PINPad в первом доступном слоте;  *
    *  - выполнение аутентификации Пользователя;                             *
    *  - подпись отображаемых платежных данных на экране PINPad;             *
    *  - проверка подписи;                                                   *
    *  - подпись запроса на сертификат для ключевой пары;                    *
    *  - проверка подписи запроса на сертификат;                             *
    *  - сброс прав доступа Пользователя на Рутокен PINPad и закрытие        *
    *    соединения с Рутокен PINPad.                                        *
    *------------------------------------------------------------------------*
    * Пример использует объекты, созданные в памяти Рутокен PINPad примером  *
    * PINPad.CreateGOST34.10-2012-512.                                       *
    *************************************************************************/

    /* Формат сообщения, распознаваемого PINPad:
    <!PINPADFILE RU>             // обязательный заголовок строки в кодировке CP-1251, которая будет отображаться на экране устройства
    <!PINPADFILE UTF8>           // обязательный заголовок строки в кодировке UTF-8, которая будет отображаться на экране устройства
    <!PINPADFILE INVISIBLE RU>   // обязательный заголовок строки в кодировке CP-1251, которая будет подписана PINPad без отображения на экране устройства
    <!PINPADFILE INVISIBLE UTF8> // обязательный заголовок строки в кодировке UTF-8, которая будет подписана PINPad без отображения на экране устройства
    <N>some text                 // наименование поля - текст будет отображен в левой части строки на экране PINPad
    <V>some text                 // значение поля - текст будет отображен в правой части строки на экране PINPad
    <T>some text                 // информационное поле - текст будет отображен на всей строке на экране PINPad
    */

    class SignGOST3410_2012_512
    {
        // Шаблон для поиска открытого ключа ГОСТ Р 34.10-2012(512)
        static readonly List<ObjectAttribute> PublicKeyAttributes = new List<ObjectAttribute>
        {
            // ID пары
            new ObjectAttribute(CKA.CKA_ID, SampleConstants.Gost512KeyPairId1),
            // Ключ ГОСТ Р 34.10-2012(512)
            new ObjectAttribute(CKA.CKA_KEY_TYPE, (uint)Extended_CKK.CKK_GOSTR3410_512),
            // Класс - открытый ключ
            new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY)
        };

        // Шаблон для поиска закрытого ключа ГОСТ Р 34.10-2012(512)
        static readonly List<ObjectAttribute> PrivateKeyAttributes = new List<ObjectAttribute>
        {
            // ID пары
            new ObjectAttribute(CKA.CKA_ID, SampleConstants.Gost512KeyPairId1),
            // Ключ ГОСТ Р 34.10-2012(512)
            new ObjectAttribute(CKA.CKA_KEY_TYPE, (uint)Extended_CKK.CKK_GOSTR3410_512),
            // Класс - закрытый ключ
            new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY)
        };

        static void Main(string[] args)
        {
            try
            {
                // Инициализировать библиотеку
                Console.WriteLine("Library initialization");
                using (var pkcs11 = new Pkcs11(Settings.RutokenEcpDllDefaultPath, AppType.MultiThreaded))
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
                    Errors.Check(" No mechanisms available", mechanisms.Count > 0);
                    bool isGostR3410_512Supported = mechanisms.Contains((CKM)Extended_CKM.CKM_GOSTR3410_512);
                    bool isGostR3411_12_512Supported = mechanisms.Contains((CKM)Extended_CKM.CKM_GOSTR3411_12_512);
                    Errors.Check(" CKM_GOSTR3410_512 isn`t supported!", isGostR3410_512Supported);
                    Errors.Check(" CKM_GOSTR3411_12_512 isn`t supported!", isGostR3411_12_512Supported);

                    // Открыть RW сессию в первом доступном слоте
                    Console.WriteLine("Opening RW session");
                    using (Session session = slot.OpenSession(SessionType.ReadWrite))
                    {
                        // Выполнить аутентификацию Пользователя
                        Console.WriteLine("User authentication");
                        session.Login(CKU.CKU_USER, SampleConstants.NormalUserPin);

                        try
                        {
                            // Получить данные для вычисления подписи
                            string sourceData = SampleData.PINPad_Sign_SourceData;

                            // Получить приватный ключ для генерации подписи
                            Console.WriteLine("Getting private key...");
                            List<ObjectHandle> privateKeys = session.FindAllObjects(PrivateKeyAttributes);
                            Errors.Check("No private keys found", privateKeys.Count > 0);

                            // Инициализировать операцию хэширования
                            var mechanism = new Mechanism((uint)Extended_CKM.CKM_GOSTR3411_12_512);

                            // Вычислить хэш-код данных
                            Console.WriteLine("Hashing data...");
                            byte[] hash = session.Digest(mechanism, ConvertUtils.Utf8StringToBytes(sourceData));

                            // Распечатать буфер, содержащий хэш-код
                            Console.WriteLine(" Hashed buffer is:");
                            Helpers.PrintByteArray(hash);
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

                            // Инициализация операции подписи данных по алгоритму ГОСТ Р 34.10-2012(512)
                            var signMechanism = new Mechanism((uint)Extended_CKM.CKM_GOSTR3410_512);

                            // Подписать данные
                            byte[] signature;
                            if (isOperationInvisible)
                            {
                                Console.WriteLine("Signing data invisible...");
                                signature = session.SignInvisible(signMechanism, privateKeys[0], hash);
                            }
                            else
                            {
                                Console.WriteLine("Signing data...");
                                signature = session.Sign(signMechanism, privateKeys[0], hash);
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
                            session.Verify(signMechanism, publicKeys[0], hash, signature, out isSignatureValid);

                            if (isSignatureValid)
                                Console.WriteLine("Verifying has been completed successfully");
                            else
                                throw new InvalidOperationException("Invalid signature");

                            // Выполнить подпись запроса на сертификат по алгоритму ГОСТ Р 34.10-2012(512)
                            Console.WriteLine("Signing certificate request...");

                            // Получить значение открытого ключа
                            Console.WriteLine(" Getting public key value");
                            attributes = new List<CKA>
                            {
                                CKA.CKA_VALUE
                            };
                            List<ObjectAttribute> publicKeyValues = session.GetAttributeValue(publicKeys[0], attributes);
                            byte[] publicKeyValue = publicKeyValues[0].GetValueAsByteArray();

                            // Распечатать буфер, содержащий открытый ключ
                            Console.WriteLine("  Public key:");
                            Helpers.PrintByteArray(publicKeyValue);

                            // Внести значение открытого ключа в запрос на сертификат
                            byte[] certificateRequest = SampleData.PINPad_Certificate_Request2;
                            const int publicKeyValueOffset = 69; // Смещение значения открытого ключа в запросе
                            for (var i = 0; i < publicKeyValue.Length; i++)
                            {
                                certificateRequest[i + publicKeyValueOffset] = publicKeyValue[i];
                            }

                            // Сформировать хэш-код от запроса на сертификат
                            Console.WriteLine(" Hashing data...");
                            byte[] certificateRequestHash = session.Digest(mechanism, certificateRequest);

                            // Распечатать буфер, содержащий хэш-код
                            Console.WriteLine(" Hashed buffer is:");
                            Helpers.PrintByteArray(certificateRequestHash);
                            Console.WriteLine("Hashing has been completed successfully");

                            /*************************************************************************
                            * Инициализировать операцию подписи данных                              *
                            ************************************************************************/
                            /*************************************************************************
                            * Для подписи запроса на сертификат в зависимости от атрибута ключа      *
                            * CKA_VENDOR_KEY_CONFIRM_OP используются функции C_EX_SignInvisibleInit  *
                            * и C_EX_SignInvisible (для значения CK_FALSE), либо C_SignInit и C_Sign *
                            * (для значения CK_TRUE)                                                 *
                            *************************************************************************/
                            if (confirm[0].GetValueAsBool())
                            {
                                Console.WriteLine(" Signing data...");
                                signature = session.Sign(signMechanism, privateKeys[0], certificateRequestHash);
                            }
                            else
                            {
                                Console.WriteLine(" Signing data invisible...");
                                signature = session.SignInvisible(signMechanism, privateKeys[0], certificateRequestHash);
                            }

                            // Распечатать буфер, содержащий подпись
                            Console.WriteLine(" Signature buffer is:");
                            Helpers.PrintByteArray(signature);
                            Console.WriteLine("Data has been signed successfully");

                            // Выполнить проверку подписи данных по алгоритму ГОСТ Р 34.10-2012(512)
                            Console.WriteLine("Verifying signature...");
                            isSignatureValid = false;
                            session.Verify(signMechanism, publicKeys[0], certificateRequestHash, signature, out isSignatureValid);

                            if (isSignatureValid)
                                Console.WriteLine("Verifying has been completed successfully");
                            else
                                throw new InvalidOperationException("Invalid signature");
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
