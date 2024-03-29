using System.Management;
using WebSpectre.Shared.Agents;

namespace PacketSniffer
{
    public static class CurrentMachineHelper
    {
        /// <summary>
        /// Получить инофрмацию о материнской плате.
        /// </summary>
        /// <returns>Информация о материнской плате в формате <see cref="MotherboardInfo"/></returns>
        public static MotherboardInfo GetMotherboardInfo()
        {
            var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_BaseBoard");
            var mboardInfo = new MotherboardInfo();

            foreach (var obj in searcher.Get())
            {
                mboardInfo.Manufacturer += obj["Manufacturer"];
                mboardInfo.Model += obj["Product"];
            }

            return mboardInfo;
        }

        /// <summary>
        /// Получить информацию об оперативной памяти.
        /// </summary>
        /// <returns>Информация об оперативной памяти в формате <see cref="MemoryInfo"/></returns>
        public static MemoryInfo GetMemoryInfo()
        {
            var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_PhysicalMemory");
            long memorySize = 0;
            foreach (var obj in searcher.Get())
            {
                memorySize += Convert.ToInt64(obj["Capacity"]);
            }

            return new MemoryInfo
            {
                TotalMemory = (int)(memorySize / (1024 * 1024))
            };
        }

        /// <summary>
        /// Получить информацию о CPU.
        /// </summary>
        /// <returns>Информация о CPU в формате <see cref="CPUInfo"/></returns>
        public static CPUInfo GetCPUInfo()
        {
            var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Processor");
            var cpu = new CPUInfo();
            foreach (var obj in searcher.Get())
            {
                cpu.Processor += obj["Name"];
                cpu.NumberOfCores += obj["NumberOfCores"];
                cpu.MaxClockSpeed += obj["MaxClockSpeed"];
            }

            return cpu;
        }

        /// <summary>
        /// Получить информацию о GPU.
        /// </summary>
        /// <returns>Информация о GPU в формате <see cref="GPUInfo"/></returns>
        public static GPUInfo GetGPUInfo()
        {
            var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_VideoController");
            var gpu = new GPUInfo();
            foreach (var obj in searcher.Get())
            {
                gpu.GraphicsCard = $"{obj["Name"]}";
            }

            return gpu;
        }
    }
}
