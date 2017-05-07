using System;
using System.Collections.Generic;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using RutokenPkcs11Interop;
using RutokenPkcs11Interop.Common;
using RutokenPkcs11Interop.Samples.Common;

namespace CreateGOST28147_89
{
    class CreateGOST28147_89
    {
        // Шаблон для создания симметричного ключа ГОСТ 28147-89
        static readonly List<ObjectAttribute> SymmetricKeyAttributes = new List<ObjectAttribute>()
        {
            new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
            new ObjectAttribute(CKA.CKA_LABEL, SampleConstants.GostSecretKeyId),
            new ObjectAttribute(CKA.CKA_ID, SampleConstants.GostSecretKeyId),
            new ObjectAttribute(CKA.CKA_KEY_TYPE, (uint) Extended_CKK.CKK_GOST28147),
            new ObjectAttribute(CKA.CKA_ENCRYPT, true),
            new ObjectAttribute(CKA.CKA_DECRYPT, true),
            new ObjectAttribute(CKA.CKA_TOKEN, true),
            new ObjectAttribute(CKA.CKA_PRIVATE, true),
            new ObjectAttribute((uint) Extended_CKA.CKA_GOST28147_PARAMS, SampleConstants.Gost28147Parameters)
        };

        static void Main(string[] args)
        {
            // Инициализировать библиотеку
            try
            {
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
                    bool isGost28147_89Supported = mechanisms.Contains((CKM) Extended_CKM.CKM_GOST28147_KEY_GEN);
                    Errors.Check("CKM_GOST28147_KEY_GEN isn`t supported!", isGost28147_89Supported);

                    // Открыть RW сессию в первом доступном слоте
                    Console.WriteLine("Opening RW session");
                    using (Session session = slot.OpenSession(false))
                    {
                        // Выполнить аутентификацию Пользователя
                        Console.WriteLine("User authentication");
                        session.Login(CKU.CKU_USER, SampleConstants.NormalUserPin);

                        // Определить механизм генерации ключа
                        Console.WriteLine("Generating GOST 28147-89 secret key...");
                        var mechanism = new Mechanism((uint)Extended_CKM.CKM_GOST28147_KEY_GEN);

                        // Сгенерировать секретный ключ ГОСТ 28147-89
                        ObjectHandle symmetricKey = session.GenerateKey(mechanism, SymmetricKeyAttributes);
                        Errors.Check("Invalid key handle", symmetricKey.ObjectId != CK.CK_INVALID_HANDLE);
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
