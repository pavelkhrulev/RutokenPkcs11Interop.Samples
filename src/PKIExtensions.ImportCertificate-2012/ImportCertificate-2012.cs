using System;
using System.Collections.Generic;
using System.Text;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using RutokenPkcs11Interop;
using RutokenPkcs11Interop.Helpers;
using RutokenPkcs11Interop.Samples.Common;

namespace PKIExtensions.ImportCertificate_2012
{
    /*************************************************************************
    * Rutoken                                                                *
    * Copyright (c) 2003-2017, CJSC Aktiv-Soft. All rights reserved.         *
    * Подробная информация:  http://www.rutoken.ru                           *
    *------------------------------------------------------------------------*
    * Пример работы с Рутокен ЭЦП при помощи библиотеки PKCS#11 на языке C   *
    *------------------------------------------------------------------------*
    * Использование команды получения информации о сертификате на токене:    *
    *  - установление соединения с Рутокен ЭЦП в первом доступном слоте;     *
    *  - выполнение аутентификации Пользователя;                             *
    *  - импорт сертификата на Рутокен;                                      *
    *  - сброс прав доступа Пользователя и закрытие соединения с Рутокен.    *
    *------------------------------------------------------------------------*
    * В примере используется ключевая пара из CreateCSR-PKCS10-2012, и       *
    * необходимо с помощью запроса из проекта CreateCSR-PKCS10-2012 получить *
    * сертификат в кодировке base64. Сертификат можно получить в любом УЦ.   *
    *************************************************************************/

    class ImportCertificate_2012
    {
        // Шаблон для импорта сертификата
        static readonly List<ObjectAttribute> CertificateAttributes = new List<ObjectAttribute>
        {
            // Объект сертификата
            new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE),
            // Идентификатор сертификата
            new ObjectAttribute(CKA.CKA_ID, SampleConstants.Gost256KeyPairId1),
            // Сертификат является объектом токена
            new ObjectAttribute(CKA.CKA_TOKEN, true),
            // Сертификат доступен без аутентификации
            new ObjectAttribute(CKA.CKA_PRIVATE, false),
            // Тип сертификата - X.509
            new ObjectAttribute(CKA.CKA_CERTIFICATE_TYPE, CKC.CKC_X_509),
            // Категория сертификата - пользовательский
            new ObjectAttribute(CKA.CKA_CERTIFICATE_CATEGORY, SampleConstants.TokenUserCertificate)
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

                    // Открыть RW сессию в первом доступном слоте
                    Console.WriteLine("Opening RW session");
                    using (Session session = slot.OpenSession(false))
                    {
                        // Выполнить аутентификацию Пользователя
                        Console.WriteLine("User authentication");
                        session.Login(CKU.CKU_USER, SampleConstants.NormalUserPin);

                        try
                        {
                            // Импорт сертификата
                            Console.WriteLine("Import certificate...");
                            // Ввод сертификата в формате base64 и перекодирование в DER
                            Console.WriteLine(" Enter certificate in base64 format:");
                            var certificateBase64 = new StringBuilder();
                            string line;
                            while ((line = Console.ReadLine()) != null && line != "")
                            {
                                certificateBase64.Append(line);
                            }
                            byte[] certificateDer = PKIHelpers.GetDerFromBase64(certificateBase64.ToString());

                            CertificateAttributes.Add(new ObjectAttribute(CKA.CKA_VALUE, certificateDer));
                            ObjectHandle certificateHandle = session.CreateObject(CertificateAttributes);
                            Errors.Check("Invalid certificate handle", certificateHandle != null);

                            Console.WriteLine("Certificate has been created successfully");
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
