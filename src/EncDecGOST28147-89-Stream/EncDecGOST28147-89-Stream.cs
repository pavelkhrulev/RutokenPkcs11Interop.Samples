using System;
using System.Collections.Generic;
using System.IO;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using RutokenPkcs11Interop;
using RutokenPkcs11Interop.Common;
using RutokenPkcs11Interop.Samples.Common;

namespace EncDecGOST28147_89_Stream
{
    class EncDecGOST28147_89_Stream
    {
        static readonly List<ObjectAttribute> SymmetricKeyAttributes = new List<ObjectAttribute>()
        {
            new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
            new ObjectAttribute(CKA.CKA_ID, SampleConstants.GostSecretKeyId),
            new ObjectAttribute(CKA.CKA_KEY_TYPE, (uint) Extended_CKK.CKK_GOST28147)
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

                        // Получить данные для шифрования
                        byte[] sourceData = SampleData.Encrypt_Gost28147_89_SourceData;

                        // Получить ключ для шифрования
                        Console.WriteLine("Getting secret key...");
                        List<ObjectHandle> keys = session.FindAllObjects(SymmetricKeyAttributes);
                        Errors.Check("No keys found", keys.Count > 0);

                        // Инициализировать операцию шифрования
                        var mechanism = new Mechanism((uint)Extended_CKM.CKM_GOST28147);

                        // Зашифровать данные
                        Console.WriteLine("Encrypting...");
                        byte[] encryptedData = null;
                        using (MemoryStream inputStream = new MemoryStream(sourceData), outputStream = new MemoryStream())
                        {
                            session.Encrypt(mechanism, keys[0], inputStream, outputStream, 8);
                            encryptedData = outputStream.ToArray();
                        }

                        // Распечатать буфер, содержащий зашифрованные данные
                        Console.WriteLine(" Encrypting buffer is:");
                        Helpers.PrintByteArray(encryptedData);
                        Console.WriteLine("Encryption has been completed successfully");

                        // Расшифровать данные
                        Console.WriteLine("Decrypting...");
                        byte[] decryptedData = null;
                        using (MemoryStream inputStream = new MemoryStream(encryptedData), outputStream = new MemoryStream())
                        {
                            session.Decrypt(mechanism, keys[0], inputStream, outputStream, 8);
                            decryptedData = outputStream.ToArray();
                        }

                        // Распечатать буфер, содержащий расшифрованные данные
                        Console.WriteLine(" Decrypted buffer is:");
                        Helpers.PrintByteArray(decryptedData);
                        Console.WriteLine("Decryption has been completed successfully");

                        // Сравнить исходные данные с расшифрованными
                        bool encryptionState = (Convert.ToBase64String(sourceData) ==
                                                Convert.ToBase64String(decryptedData));
                        Errors.Check("Source data and decrypted data are not equal", encryptionState);

                        Console.WriteLine("Source data and decrypted data are equal");

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
