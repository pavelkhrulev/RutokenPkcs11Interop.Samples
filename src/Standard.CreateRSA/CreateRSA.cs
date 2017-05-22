using System;
using System.Collections.Generic;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using RutokenPkcs11Interop;
using RutokenPkcs11Interop.Samples.Common;

namespace CreateRSA
{
    class CreateRSA
    {
        // Шаблон для генерации открытого ключа RSA
        // (Ключевая пара для подписи и шифрования)
        static readonly List<ObjectAttribute> PublicKeyAttributes = new List<ObjectAttribute>()
        {
            new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY),
            new ObjectAttribute(CKA.CKA_LABEL, SampleConstants.RsaPublicKeyLabel),
            new ObjectAttribute(CKA.CKA_ID, SampleConstants.RsaKeyPairId),
            new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_RSA),
            new ObjectAttribute(CKA.CKA_TOKEN, true),
            new ObjectAttribute(CKA.CKA_ENCRYPT, true),
            new ObjectAttribute(CKA.CKA_PRIVATE, false),
            new ObjectAttribute(CKA.CKA_MODULUS_BITS, SampleConstants.RsaModulusBits)
        };

        // Шаблон для генерации закрытого ключа RSA
        // (Ключевая пара для подписи и шифрования)
        static readonly List<ObjectAttribute> PrivateKeyAttributes = new List<ObjectAttribute>()
        {
            new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
            new ObjectAttribute(CKA.CKA_LABEL, SampleConstants.RsaPrivateKeyLabel),
            new ObjectAttribute(CKA.CKA_ID, SampleConstants.RsaKeyPairId),
            new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_RSA),
            new ObjectAttribute(CKA.CKA_TOKEN, true),
            new ObjectAttribute(CKA.CKA_DECRYPT, true),
            new ObjectAttribute(CKA.CKA_PRIVATE, true),
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
                    Errors.Check("No mechanisms available", mechanisms.Count > 0);
                    bool isRsaSupported = mechanisms.Contains(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN);
                    Errors.Check("CKM_RSA_PKCS_KEY_PAIR_GEN isn`t supported!", isRsaSupported);

                    // Открыть RW сессию в первом доступном слоте
                    Console.WriteLine("Opening RW session");
                    using (Session session = slot.OpenSession(false))
                    {
                        // Выполнить аутентификацию Пользователя
                        Console.WriteLine("User authentication");
                        session.Login(CKU.CKU_USER, SampleConstants.NormalUserPin);

                        // Определить механизм генерации ключа
                        Console.WriteLine("Generating RSA key pair...");
                        var mechanism = new Mechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN);

                        // Сгенерировать ключевую пару RSA
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
