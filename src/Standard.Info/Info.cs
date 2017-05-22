using System;
using System.Collections.Generic;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using RutokenPkcs11Interop;
using RutokenPkcs11Interop.Common;
using RutokenPkcs11Interop.Samples.Common;

namespace Info
{
    class Info
    {
        static void Main(string[] args)
        {
            try
            {
                // Инициализировать библиотеку
                Console.WriteLine("Library initialization");
                using (var pkcs11 = new Pkcs11(Settings.RutokenEcpDllDefaultPath, Settings.OsLockingDefault))
                {
                    // Получить информацию о библиотеке
                    Console.WriteLine("Getting library info");
                    LibraryInfo libraryInfo = pkcs11.GetInfo();
                    Console.WriteLine("Printing library info:");
                    Console.WriteLine(" PKCS#11 version: {0}", libraryInfo.CryptokiVersion);
                    Console.WriteLine(" Manufacturer: {0}", libraryInfo.ManufacturerId);
                    Console.WriteLine(" Flags: 0x{0:X}", libraryInfo.Flags);
                    Console.WriteLine(" Library description: {0}", libraryInfo.LibraryDescription);
                    Console.WriteLine();

                    // Получить слоты
                    Console.WriteLine("Checking slots available");
                    List<Slot> slots = pkcs11.GetSlotList(true);
                    // Проверить, что слоты найдены
                    if (slots == null)
                        throw new NullReferenceException("No available slots");
                    // Проверить, что число слотов больше 0
                    if (slots.Count <= 0)
                        throw new InvalidOperationException("No available slots");

                    // Распечатать информацию:
                    //        - о слотах;
                    //        - о подключенных токенах;
                    //        - о поддерживаемых механизмах.
                    foreach (var slot in slots)
                    {
                        SlotInfo slotInfo = slot.GetSlotInfo();

                        // Распечатать информацию о слоте
                        Console.WriteLine("Printing slot info:");
                        Console.WriteLine(" Slot description: {0}", slotInfo.SlotDescription);
                        Console.WriteLine(" Manufacturer: {0}", slotInfo.ManufacturerId);
                        Console.WriteLine(" Flags: 0x{0:X}", slotInfo.SlotFlags.Flags);
                        Console.WriteLine(" Hardware version: {0}", slotInfo.HardwareVersion);
                        Console.WriteLine(" Firmware version: {0}", slotInfo.FirmwareVersion);
                        Console.WriteLine();

                        if (slotInfo.SlotFlags.TokenPresent)
                        {
                            // Получить информацию о токене
                            TokenInfo tokenInfo = slot.GetTokenInfo();

                            // Распечатать информацию о токене
                            Console.WriteLine("Printing token info:");
                            Console.WriteLine(" Label: {0}", tokenInfo.Label);
                            Console.WriteLine(" Manufacturer: {0}", tokenInfo.ManufacturerId);
                            Console.WriteLine(" Token model: {0}", tokenInfo.Model);
                            Console.WriteLine(" Token #: {0}", tokenInfo.SerialNumber);
                            Console.WriteLine(" Flags: 0x{0:X}", tokenInfo.TokenFlags.Flags);
                            Console.WriteLine(" Max session count: {0}", tokenInfo.MaxSessionCount);
                            Console.WriteLine(" Current session count: {0}", tokenInfo.SessionCount);
                            Console.WriteLine(" Max RW session count: {0}", tokenInfo.MaxRwSessionCount);
                            Console.WriteLine(" Current RW session count: {0}", tokenInfo.RwSessionCount);
                            Console.WriteLine(" Max PIN length: {0}", tokenInfo.MaxPinLen);
                            Console.WriteLine(" Min PIN length: {0}", tokenInfo.MinPinLen);
                            Console.WriteLine(" Total public memory: {0}", tokenInfo.TotalPublicMemory);
                            Console.WriteLine(" Free public memory: {0}", tokenInfo.FreePublicMemory);
                            Console.WriteLine(" Total private memory: {0}", tokenInfo.TotalPrivateMemory);
                            Console.WriteLine(" Free private memory: {0}", tokenInfo.FreePrivateMemory);
                            Console.WriteLine(" Hardware version: {0}", tokenInfo.HardwareVersion);
                            Console.WriteLine(" Firmware version: {0}", tokenInfo.FirmwareVersion);
                            Console.WriteLine(" Timer #: {0}", tokenInfo.UtcTime);
                            Console.WriteLine();

                            // Получить список поддерживаемых токеном механизмов
                            Console.WriteLine("Checking mechanisms available");
                            List<CKM> mechanisms = slot.GetMechanismList();
                            Errors.Check("No mechanisms available", mechanisms.Count > 0);

                            foreach (var mechanism in mechanisms)
                            {
                                MechanismInfo mechanismInfo = slot.GetMechanismInfo(mechanism);
                                Console.WriteLine("Printing mechanism info:");
                                if (Enum.IsDefined(typeof(Extended_CKM), (Extended_CKM)mechanismInfo.Mechanism))
                                {
                                    Console.WriteLine(" Mechanism type: {0}", (Extended_CKM)mechanismInfo.Mechanism);
                                }
                                else
                                {
                                    Console.WriteLine(" Mechanism type: {0}", mechanismInfo.Mechanism);
                                }
                                Console.WriteLine(" Min key size: {0}", mechanismInfo.MinKeySize);
                                Console.WriteLine(" Max key size: {0}", mechanismInfo.MaxKeySize);
                                Console.WriteLine(" Mechanism flags: 0x{0:X}", mechanismInfo.MechanismFlags.Flags);
                                Console.WriteLine();
                            }
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
