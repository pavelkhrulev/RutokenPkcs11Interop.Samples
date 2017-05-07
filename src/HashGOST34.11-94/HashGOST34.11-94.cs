using System;
using System.Collections.Generic;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using RutokenPkcs11Interop;
using RutokenPkcs11Interop.Common;
using RutokenPkcs11Interop.Samples.Common;

namespace HashGOST3411_94
{
    class HashGOST3411_94
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

                    // Определение поддерживаемых токеном механизмов
                    Console.WriteLine("Checking mechanisms available");
                    List<CKM> mechanisms = slot.GetMechanismList();
                    Errors.Check("No mechanisms available", mechanisms.Count > 0);
                    bool isGostR3411Supported = mechanisms.Contains((CKM)Extended_CKM.CKM_GOSTR3411);
                    Errors.Check("CKM_GOSTR3411 isn`t supported!", isGostR3411Supported);

                    // Открыть RW сессию в первом доступном слоте
                    Console.WriteLine("Opening RW session");
                    using (Session session = slot.OpenSession(false))
                    {
                        // Выполнить аутентификацию Пользователя
                        Console.WriteLine("User authentication");
                        session.Login(CKU.CKU_USER, SampleConstants.NormalUserPin);

                        // Получить данные для хэширования
                        byte[] sourceData = SampleData.Digest_Gost3411_SourceData;

                        // Инициализировать операцию хэширования
                        var mechanism = new Mechanism((uint)Extended_CKM.CKM_GOSTR3411);

                        // Вычислить хэш-код данных
                        Console.WriteLine("Hashing data...");
                        byte[] hash = session.Digest(mechanism, sourceData);

                        // Распечатать буфер, содержащий хэш-код
                        Console.WriteLine(" Hashed buffer is:");
                        Helpers.PrintByteArray(hash);
                        Console.WriteLine("Hashing has been completed successfully");

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
