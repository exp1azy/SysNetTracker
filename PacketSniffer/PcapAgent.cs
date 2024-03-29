using SharpPcap.LibPcap;
using SharpPcap.Statistics;
using StackExchange.Redis;
using System.Net;
using SharpPcap;
using Newtonsoft.Json;
using PacketSniffer.Resources;
using System.Collections.Concurrent;
using Serilog;
using WebSpectre.Shared.Agents;
using PcapDevice = WebSpectre.Shared.Agents.PcapDevice;
using System.Net.NetworkInformation;
using NetworkInterface = System.Net.NetworkInformation.NetworkInterface;

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

        private ConcurrentQueue<StatisticsEventArgs> _statisticsQueue;
        private ConcurrentQueue<RawCapture> _rawPacketsQueue;

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

            _statisticsQueue = new ConcurrentQueue<StatisticsEventArgs>();
            _rawPacketsQueue = new ConcurrentQueue<RawCapture>();

            if (int.TryParse(_config["MaxQueueSize"], out var maxQueueSize))
            {
                _maxQueueSize = maxQueueSize;
            }
            else
            {
                _maxQueueSize = 20;
                Log.Logger.Warning(Error.FailedToReadQueuesSizeData);
            }
        }

        /// <summary>
        /// <see cref="true"/>, если захват трафика запущен, иначе <see cref="false"/>.
        /// </summary>
        public bool IsSnifferCapturing => _isSnifferCapturing;

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
            {
                Log.Logger.Error(Error.FailedToReadRedisConnectionString);
                throw new ApplicationException(Error.FailedToReadRedisConnectionString);
            }

            var os = Environment.OSVersion;
            if (os.Platform != PlatformID.Win32NT)
            {
                Log.Logger.Error(Error.UnsupportedOS);
                throw new ApplicationException(Error.UnsupportedOS);
            }

            var devices = LibPcapLiveDeviceList.Instance;
            if (devices.Count < 1)
            {
                Log.Logger.Error(Error.NoDevicesWereFound);
                throw new ApplicationException(Error.NoDevicesWereFound);
            }

            int interfaceIndex = GetInterfaceIndex(devices, adapter);
            if (interfaceIndex < 0)
            {
                Log.Logger.Error(Error.NoSuchInterface, adapter);
                throw new ApplicationException($"{Error.NoSuchInterface} {adapter}");
            }
             
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

            Log.Logger.Information(Information.LocalSniffingStarted);
        }

        /// <summary>
        /// Остановить захват сетевого трафика.
        /// </summary>
        public void Stop()
        {
            if (_captureTask != null)
            {
                _captureCancellation!.Cancel();

                _captureTask?.Wait();

                _captureCancellation.Dispose();
                _captureCancellation = null;

                _isSnifferCapturing = false;

                Log.Logger.Information(Information.LocalSniffingStopped);
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
            var filter = _config["Filters"];
            if (string.IsNullOrEmpty(filter))
            {
                Log.Logger.Error(Error.FailedToReadProtocols);
                throw new ApplicationException(Error.FailedToReadProtocols);
            }

            using var statisticsDevice = new StatisticsDevice(devices[interfaceToSniff].Interface);
            using var device = devices[interfaceToSniff];

            statisticsDevice.OnPcapStatistics += Device_OnPcapStatistics!;
            device.OnPacketArrival += new PacketArrivalEventHandler(Device_OnPacketArrival);

            statisticsDevice.Open();
            device.Open();

            statisticsDevice.StartCapture();
            device.StartCapture();

            while (!cancellationToken.IsCancellationRequested)
                await Task.Delay(2000);

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
            var rawPacket = e.GetPacket();

            if (_rawPacketsQueue.Count < _maxQueueSize)
                _rawPacketsQueue.Enqueue(rawPacket);                           
            else
                HandleRawPacketsQueueAsync().Wait();                                    
        }

        /// <summary>
        /// Метод-обработчик события OnPcapStatistics.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void Device_OnPcapStatistics(object sender, StatisticsEventArgs e)
        {          
            if (_statisticsQueue.Count < _maxQueueSize)          
                _statisticsQueue.Enqueue(e);                               
            else          
                HandleStatisticsQueueAsync().Wait();      
        }

        /// <summary>
        /// Метод, необходимый для массовой загрузки сырых пакетов в поток Redis из очереди.
        /// </summary>
        /// <returns></returns>
        private async Task HandleRawPacketsQueueAsync()
        {
            var entries = new List<NameValueEntry>();

            while (_rawPacketsQueue.TryDequeue(out var rawPacket))              
                entries.Add(new NameValueEntry(_rawPacketValueKey, JsonConvert.SerializeObject(rawPacket))); 

            await _redisService.StreamAddAsync([.. entries]);
        }

        /// <summary>
        /// Метод, необходимый для массовой загрузки статистики в поток Redis из очереди.
        /// </summary>
        /// <returns></returns>
        private async Task HandleStatisticsQueueAsync()
        {
            var entries = new List<NameValueEntry>();

            while (_statisticsQueue.TryDequeue(out var statistics))
                entries.Add(new NameValueEntry(_statisticsValueKey, JsonConvert.SerializeObject(statistics)));

            await _redisService.StreamAddAsync([.. entries]);         
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