using System;
using System.Linq;
using System.Threading.Tasks;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using RutokenPkcs11Interop;

namespace WaitForSlotEvent
{
    /*************************************************************************
    * Rutoken                                                                *
    * Copyright (c) 2003-2019, CJSC Aktiv-Soft. All rights reserved.         *
    * Подробная информация:  http://www.rutoken.ru                           *
    *------------------------------------------------------------------------*
    * Пример работы с Рутокен при помощи библиотеки PKCS#11 на языке C       *
    *------------------------------------------------------------------------*
    * Использование команд получения информации о событиях в слотах:         *
    *  - инициализация библиотеки;                                           *
    *  - проверка события в каком-либо слоте (без блокировки                 *
    *    выполнения потока приложения);                                      *
    *  - ожидание события потоком в каком-либо слоте (с блокировкой          *
    *    выполнения потока приложения).                                      *
    *------------------------------------------------------------------------*
    * Данный пример является самодостаточным.                                *
    *************************************************************************/

    class WaitForSlotEvent
    {
        private static void MonitoringTask(Pkcs11 pkcs11, int taskNumber)
        {
            while (true)
            {
                // Ожидать событие в некотором слоте
                bool eventOccured;
                ulong slotId;
                pkcs11.WaitForSlotEvent(WaitType.Blocking, out eventOccured, out slotId);

                // Получить информацию о слоте
                Slot slot = pkcs11.GetSlotList(SlotsType.WithOrWithoutTokenPresent).Single(x => x.SlotId == slotId);
                SlotInfo slotInfo = slot.GetSlotInfo();

                // Распечатать информацию о номере потока и событии в слоте
                Console.WriteLine(" Monitoring thread: {0}", taskNumber);
                Console.WriteLine(" Slot ID: {0}", slotId);
                Console.WriteLine(slotInfo.SlotFlags.TokenPresent
                    ? "  Token has been attached!"
                    : "  Token has been detached!");
            }
        }

        static void Main(string[] args)
        {
            try
            {
                // Инициализировать библиотеку
                Console.WriteLine("Library initialization");
                using (var pkcs11 = new Pkcs11(Settings.RutokenEcpDllDefaultPath, AppType.MultiThreaded))
                {
                    Console.WriteLine("Please attach or detach Rutoken and press Enter...");
                    Console.ReadKey();

                    for (var i = 0;; i++)
                    {
                        // Получить все события в слотах
                        // (не блокируя поток, используем флаг CKF_DONT_BLOCK)
                        bool eventOccured;
                        ulong slotId;
                        pkcs11.WaitForSlotEvent(WaitType.NonBlocking, out eventOccured, out slotId);
                        if (!eventOccured)
                        {
                            break;
                        }

                        // Получить информацию о слоте
                        Slot slot = pkcs11.GetSlotList(SlotsType.WithOrWithoutTokenPresent).Single(x => x.SlotId == slotId);
                        SlotInfo slotInfo = slot.GetSlotInfo();
                        Console.WriteLine(" Slot ID: {0}", slotId);
                        Console.WriteLine(" Slot description: {0}", slotInfo.SlotDescription);
                        Console.WriteLine(" Manufacturer: {0}", slotInfo.ManufacturerId);
                        Console.WriteLine(" Flags: 0x{0:X}", slotInfo.SlotFlags.Flags);
                        Console.WriteLine(" Hardware version: {0}", slotInfo.HardwareVersion);
                        Console.WriteLine(" Firmware version: {0}", slotInfo.FirmwareVersion);
                    }

                    // Запустить поток, ожидающий событие в каком-либо слоте.
                    // До наступления события выполнение запущенного потока заблокировано.
                    // Первое же событие разблокирует выполнение ожидающего потока.
                    // TODO: есть проблема с не срабатыванием события при числе потоков более одного
                    var tasksCount = 1;
                    for (var i = 0; i < tasksCount; i++)
                    {
                        var taskNumber = i;
                        Console.WriteLine("Starting monitoring thread number: {0}", taskNumber);
                        Task.Run(() => MonitoringTask(pkcs11, taskNumber));
                    }

                    Console.WriteLine("Please attach or detach Rutoken or press Enter to exit.");
                    Console.ReadKey();
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
