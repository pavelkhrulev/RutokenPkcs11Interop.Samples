using System;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using RutokenPkcs11Interop;
using RutokenPkcs11Interop.Samples.Common;

namespace PKIExtensions.VerifyPKCS7
{
    /*************************************************************************
    * Rutoken                                                                *
    * Copyright (c) 2003-2019, CJSC Aktiv-Soft. All rights reserved.         *
    * Подробная информация:  http://www.rutoken.ru                           *
    *------------------------------------------------------------------------*
    * Пример работы с Рутокен ЭЦП при помощи библиотеки PKCS#11 на языке C#  *
    *------------------------------------------------------------------------*
    * Использование команды проверки подписанных данных ключевой парой       *
    * ГОСТ Р 34.10 в формате PKCS#7:                                         *
    *  - установление соединения с Рутокен ЭЦП в первом доступном слоте;     *
    *  - выполнение аутентификации Пользователя;                             *
    *  - проверка подписанных данных в формате PKCS#7;                       *
    *  - сброс прав доступа Пользователя и закрытие соединения с Рутокен.    *
    *                                                                        *
    *------------------------------------------------------------------------*
    * Пример использует объекты, созданные в памяти примерами:               *
    *                                                                        *
    * Для алгоритма ГОСТ Р 34.10-2001:                                       *
    * PKIExtensions.ImportCertificate-GOST34.10-2001 и                       *
    * PKIExtensions.SignPKCS7-GOST34.10-2001.                                *
    *                                                                        *
    * Для алгоритма ГОСТ Р 34.10-2012 с длиной закрытого ключа 256 бит:      *
    * PKIExtensions.ImportCertificate-GOST34.10-2012-256 и                   *
    * PKIExtensions.SignPKCS7-GOST34.10-2012-256.                            *
    *                                                                        *
    * Для алгоритма ГОСТ Р 34.10-2012 с длиной закрытого ключа 512 бит:      *
    * PKIExtensions.ImportCertificate-GOST34.10-2012-512 и                   *
    * PKIExtensions.SignPKCS7-GOST34.10-2012-512.                            *
    *                                                                        *
    * Также необходимо предоставить сертификат УЦ, в котором был выписан     *
    * сертификат в кодировке base64 или DER.                                 *
    *************************************************************************/

    class VerifyPKCS7
    {
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
                            // Проверка подписи
                            Console.WriteLine("Verifying...");
                            // TODO: реализовать функцию в библиотеке и прикрутить сюда ее вызов
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
