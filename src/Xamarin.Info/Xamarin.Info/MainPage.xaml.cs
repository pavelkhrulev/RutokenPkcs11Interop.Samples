using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using RutokenPkcs11Interop;
using RutokenPkcs11Interop.Common;
using System;
using System.Collections.Generic;
using Xamarin.Forms;

namespace Xamarin.Info
{
    public partial class MainPage : ContentPage
    {
        public MainPage()
        {
            InitializeComponent();
        }

        private void Button_OnClicked(object sender, EventArgs e)
        {
            try
            {
                // Инициализировать библиотеку
                InfoLabel.Text += ("Library initialization");
                using (var pkcs11 = new Pkcs11(Settings.RutokenEcpDllDefaultPath, AppType.MultiThreaded))
                {
                    // Получить информацию о библиотеке
                    InfoLabel.Text = "Getting library info";
                    LibraryInfo libraryInfo = pkcs11.GetInfo();
                    InfoLabel.Text += ("Printing library info:");
                    InfoLabel.Text += (" PKCS#11 version: {0}", libraryInfo.CryptokiVersion);
                    InfoLabel.Text += (" Manufacturer: {0}", libraryInfo.ManufacturerId);
                    InfoLabel.Text += (" Flags: 0x{0:X}", libraryInfo.Flags);
                    InfoLabel.Text += (" Library description: {0}", libraryInfo.LibraryDescription);
                    InfoLabel.Text += "\n";

                    // Получить слоты
                    InfoLabel.Text += ("Checking slots available");
                    List<Slot> slots = pkcs11.GetSlotList(SlotsType.WithTokenPresent);
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
                        InfoLabel.Text += ("Printing slot info:");
                        InfoLabel.Text += (" Slot description: {0}", slotInfo.SlotDescription);
                        InfoLabel.Text += (" Manufacturer: {0}", slotInfo.ManufacturerId);
                        InfoLabel.Text += (" Flags: 0x{0:X}", slotInfo.SlotFlags.Flags);
                        InfoLabel.Text += (" Hardware version: {0}", slotInfo.HardwareVersion);
                        InfoLabel.Text += (" Firmware version: {0}", slotInfo.FirmwareVersion);
                        InfoLabel.Text += "\n";

                        if (slotInfo.SlotFlags.TokenPresent)
                        {
                            // Получить информацию о токене
                            TokenInfo tokenInfo = slot.GetTokenInfo();

                            // Распечатать информацию о токене
                            InfoLabel.Text += ("Printing token info:");
                            InfoLabel.Text += (" Label: {0}", tokenInfo.Label);
                            InfoLabel.Text += (" Manufacturer: {0}", tokenInfo.ManufacturerId);
                            InfoLabel.Text += (" Token model: {0}", tokenInfo.Model);
                            InfoLabel.Text += (" Token #: {0}", tokenInfo.SerialNumber);
                            InfoLabel.Text += (" Flags: 0x{0:X}", tokenInfo.TokenFlags.Flags);
                            InfoLabel.Text += (" Max session count: {0}", tokenInfo.MaxSessionCount);
                            InfoLabel.Text += (" Current session count: {0}", tokenInfo.SessionCount);
                            InfoLabel.Text += (" Max RW session count: {0}", tokenInfo.MaxRwSessionCount);
                            InfoLabel.Text += (" Current RW session count: {0}", tokenInfo.RwSessionCount);
                            InfoLabel.Text += (" Max PIN length: {0}", tokenInfo.MaxPinLen);
                            InfoLabel.Text += (" Min PIN length: {0}", tokenInfo.MinPinLen);
                            InfoLabel.Text += (" Total public memory: {0}", tokenInfo.TotalPublicMemory);
                            InfoLabel.Text += (" Free public memory: {0}", tokenInfo.FreePublicMemory);
                            InfoLabel.Text += (" Total private memory: {0}", tokenInfo.TotalPrivateMemory);
                            InfoLabel.Text += (" Free private memory: {0}", tokenInfo.FreePrivateMemory);
                            InfoLabel.Text += (" Hardware version: {0}", tokenInfo.HardwareVersion);
                            InfoLabel.Text += (" Firmware version: {0}", tokenInfo.FirmwareVersion);
                            InfoLabel.Text += (" Timer #: {0}", tokenInfo.UtcTime);
                            InfoLabel.Text += "\n";

                            // Получить список поддерживаемых токеном механизмов
                            InfoLabel.Text += ("Checking mechanisms available");
                            List<CKM> mechanisms = slot.GetMechanismList();
                            if (mechanisms.Count == 0)
                            {
                                throw new InvalidOperationException("No mechanism available");
                            };

                            foreach (var mechanism in mechanisms)
                            {
                                MechanismInfo mechanismInfo = slot.GetMechanismInfo(mechanism);
                                InfoLabel.Text += ("Printing mechanism info:");
                                if (Enum.IsDefined(typeof(Extended_CKM), (Extended_CKM)mechanismInfo.Mechanism))
                                {
                                    InfoLabel.Text += (" Mechanism type: {0}", (Extended_CKM)mechanismInfo.Mechanism);
                                }
                                else
                                {
                                    InfoLabel.Text += (" Mechanism type: {0}", mechanismInfo.Mechanism);
                                }
                                InfoLabel.Text += (" Min key size: {0}", mechanismInfo.MinKeySize);
                                InfoLabel.Text += (" Max key size: {0}", mechanismInfo.MaxKeySize);
                                InfoLabel.Text += (" Mechanism flags: 0x{0:X}", mechanismInfo.MechanismFlags.Flags);
                                InfoLabel.Text += "\n";
                            }
                        }
                    }
                }
            }
            catch (Pkcs11Exception ex)
            {
                InfoLabel.Text += ($"Operation failed [Method: {ex.Method}, RV: {ex.RV}]");
            }
            catch (Exception ex)
            {
                InfoLabel.Text += ($"Operation failed [Message: {ex.Message}]");
            }
        }
    }
}
