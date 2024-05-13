using SharpPcap.LibPcap;
using SharpPcap.Statistics;
using StackExchange.Redis;
using System.Net;
using SharpPcap;
using Newtonsoft.Json;
using PacketSniffer.Resources;
using System.Collections.Concurrent;
using WebSpectre.Shared.Agents;
using PcapDevice = WebSpectre.Shared.Agents.PcapDevice;
using NetworkInterface = System.Net.NetworkInformation.NetworkInterface;
using WebSpectre.Shared;

namespace PacketSniffer
{
    /// <summary>
    /// Класс-обработчик сетевого трафика.
    /// </summary>
    public class PcapAgent
    {
        private readonly IConfiguration _config;
        private readonly RedisService _redisService;
        private readonly int _maxQueueSize;

        private Task? _captureTask;
        private CancellationTokenSource? _captureCancellation;

        private readonly List<StatisticsEventArgs> _statisticsBatch;
        private readonly List<RawCapture> _rawPacketsBatch;

        private readonly object _lockPackets = new ();
        private readonly object _lockStatistics = new ();

        private const string _rawPacketValueKey = "raw_packets";
        private const string _statisticsValueKey = "statistics";

        private bool _isSnifferCapturing = false;

        /// <summary>
        /// Конструктор <see cref="PcapAgent"/>.
        /// </summary>
        /// <param name="config">Файл конфигурации.</param>
        public PcapAgent(IConfiguration config, RedisService redisService)
        {
            _config = config;
            _redisService = redisService;

            _statisticsBatch = new List<StatisticsEventArgs>(_maxQueueSize);
            _rawPacketsBatch = new List<RawCapture>(_maxQueueSize);

            if (int.TryParse(_config["MaxQueueSize"], out var maxQueueSize))
                _maxQueueSize = maxQueueSize;
            else
                _maxQueueSize = 20;
        }

        /// <summary>
        /// Метод, необходимый для получения информации о хосте.
        /// </summary>
        /// <returns>Информация о текущем хосте в формате <see cref="HostInfo"/></returns>
        public HostInfo GetHostInfo() => new()
        {
            MachineName = Environment.MachineName,
            OSVersion = Environment.OSVersion.VersionString,
            Hardware = new Hardware 
            { 
                MotherboardInfo = CurrentMachineHelper.GetMotherboardInfo(),
                MemoryInfo = CurrentMachineHelper.GetMemoryInfo(),
                CPUInfo = CurrentMachineHelper.GetCPUInfo(),
                GPUInfo = CurrentMachineHelper.GetGPUInfo()
            },
            IPAddresses = Dns.GetHostAddresses(Dns.GetHostName()).Select(ip => ip.ToString()).ToArray(),
            NetworkInformation = NetworkInterface.GetAllNetworkInterfaces().Select(i => (NetworkInformation)i).ToList(),
            ResourcesUsage = CurrentMachineHelper.GetCurrentUsage(),
            IsCaptureProcessing = _isSnifferCapturing
        };           
           
        /// <summary>
        /// Получить доступные сетевые адаптеры.
        /// </summary>
        /// <returns>Список устройств.</returns>
        public List<PcapDevice> GetDevices()
        {
            var devices = LibPcapLiveDeviceList.Instance;
            if (devices.Count < 1)           
                throw new ApplicationException();

            var formattedDevices = new List<PcapDevice>();
            
            foreach (var device in devices)
            {
                formattedDevices.Add(new PcapDevice
                {
                    Addresses = device.Interface.Addresses.Select(a => (WebSpectre.Shared.Agents.PcapAddress)a).ToList(),
                    Description = device.Interface.Description,
                    FriendlyName = device.Interface.FriendlyName,
                    GatewayAddresses = device.Interface.GatewayAddresses.Select(a => a.ToString()).ToList(),
                    MacAddress = device.Interface.MacAddress?.ToString(),
                });
            }

            return formattedDevices;
        }

        /// <summary>
        /// Запустить захват сетевого трафика по указанному устройству.
        /// </summary>
        /// <param name="adapter">Устройство, по которому необходимо запустить прослушивание сетевого трафика.</param>
        /// <exception cref="ApplicationException"></exception>
        public void Start(string adapter)
        {
            if (string.IsNullOrEmpty(_config["RedisConnection"]))
                throw new ApplicationException(Error.FailedToReadRedisConnectionString);

            var os = Environment.OSVersion;
            if (os.Platform != PlatformID.Win32NT)
                throw new ApplicationException(Error.UnsupportedOS);

            var devices = LibPcapLiveDeviceList.Instance;
            if (devices.Count < 1)
                throw new ApplicationException(Error.NoDevicesWereFound);

            int interfaceIndex = GetInterfaceIndex(devices, adapter.Trim());
            if (interfaceIndex < 0)
                throw new ApplicationException($"{Error.NoSuchInterface} {adapter}");
             
            if (_captureTask == null || _captureTask.IsCompleted)
            {
                _captureCancellation = new CancellationTokenSource();

                try
                {
                    _captureTask = ListenRequiredInterfaceAsync(devices, interfaceIndex, _captureCancellation.Token);

                    _isSnifferCapturing = true;
                }
                catch (ApplicationException)
                {
                    _isSnifferCapturing = false;
                    throw;
                }
            }
            else
            {
                _isSnifferCapturing = true;
            }
        }

        /// <summary>
        /// Остановить захват сетевого трафика.
        /// </summary>
        public void Stop()
        {
            if (_captureTask != null)
            {
                _captureCancellation!.Cancel();

                _captureCancellation.Dispose();
                _captureCancellation = null;

                _isSnifferCapturing = false;
            }
        }

        /// <summary>
        /// Слушает сетевой трафик по указанному индексу устройства.
        /// </summary>
        /// <param name="devices">Сетевые устройства.</param>
        /// <param name="interfaceToSniff">Индекс устройства, с которого осуществляется перехват сетевого трафика</param>
        /// <param name="cancellationToken">Токен отмены.</param>
        /// <returns></returns>
        /// <exception cref="ApplicationException"></exception>
        private async Task ListenRequiredInterfaceAsync(LibPcapLiveDeviceList devices, int interfaceToSniff, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(_config["Filter"]))
                throw new ApplicationException();

            using var statisticsDevice = new StatisticsDevice(devices[interfaceToSniff].Interface);
            using var device = devices[interfaceToSniff];

            statisticsDevice.OnPcapStatistics += Device_OnPcapStatistics!;
            device.OnPacketArrival += new PacketArrivalEventHandler(Device_OnPacketArrival);

            statisticsDevice.Open();
            device.Open();

            statisticsDevice.Filter = _config["Filter"];
            device.Filter = _config["Filter"];

            statisticsDevice.StartCapture();
            device.StartCapture();

            while (!cancellationToken.IsCancellationRequested)
                await Task.Delay(1000, cancellationToken);
            
            statisticsDevice.StopCapture();
            device.StopCapture();
        }

        /// <summary>
        /// Метод-обработчик события OnPacketArrival.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void Device_OnPacketArrival(object sender, PacketCapture e)
        {
            lock (_lockPackets)
            {
                var rawPacket = e.GetPacket();
                _rawPacketsBatch.Add(rawPacket);

                if (_rawPacketsBatch.Count >= _maxQueueSize)
                {
                    var packets = _rawPacketsBatch.ToList();
                    _rawPacketsBatch.Clear();

                    _ = _redisService.StreamAddAsync(
                        packets.Select(p => new NameValueEntry(_rawPacketValueKey, JsonConvert.SerializeObject(p))).ToArray()
                    );
                }
            }
        }

        /// <summary>
        /// Метод-обработчик события OnPcapStatistics.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void Device_OnPcapStatistics(object sender, StatisticsEventArgs e)
        {
            _statisticsBatch.Add(e);

            if (_statisticsBatch.Count >= _maxQueueSize)
            {
                var statistics = _statisticsBatch.ToList();
                _statisticsBatch.Clear();                

                _ = _redisService.StreamAddAsync(
                    statistics.Select(s => new NameValueEntry(_statisticsValueKey, JsonConvert.SerializeObject(s))).ToArray()
                );
            }
        }

        /// <summary>
        /// Получить индекс запрашиваемого устройства.
        /// </summary>
        /// <param name="devices">Устройства.</param>
        /// <param name="interfaceToSniff">Интерфейс, необходимый для захвата пакетов.</param>
        /// <returns>Индекс устройства.</returns>
        private int GetInterfaceIndex(LibPcapLiveDeviceList devices, string interfaceToSniff) =>
            devices.IndexOf(devices.FirstOrDefault(d => d.Description == interfaceToSniff));
    }
}