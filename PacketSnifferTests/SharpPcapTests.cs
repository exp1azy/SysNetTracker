using SharpPcap;
using SharpPcap.LibPcap;
using System.Net.Sockets;
using System.Net;

namespace PacketSnifferTests
{
    public class SharpPcapTests
    {
        private const string _physicAdapterPrexif = "Realtek";
        private const string _virtualAdapterPrefix = "WireGuard";
        private const string _virtualIpPrefix = "10";

        [Fact]
        public void GetDevicesTest()
        {
            var devices = CaptureDeviceList.Instance;
            var devices1 = LibPcapLiveDeviceList.Instance;

            Assert.True(devices.Count == devices1.Count);
        }

        [Fact]
        public void CatchVirtualAdapterTest()
        {
            var devices = LibPcapLiveDeviceList.Instance;
            Assert.True(devices.Count > 0);

            var virtualIp = GetIPs().FirstOrDefault(addr => addr.ToString().StartsWith(_virtualIpPrefix));

            Assert.True(virtualIp != null);
        }

        [Fact]
        public void CheckVirtualAdapterInList()
        {
            var devices = LibPcapLiveDeviceList.Instance;
            var index = GetInterfaceIndex(devices, _virtualAdapterPrefix);

            Assert.True(index > -1);
        }

        private int GetInterfaceIndex(LibPcapLiveDeviceList devices, string interfaceToSniff) =>
            devices.IndexOf(devices.First(d => d.Description.Contains(interfaceToSniff)));

        private IEnumerable<IPAddress> GetIPs() =>
            Dns.GetHostAddresses(Dns.GetHostName()).Where(addr => addr.AddressFamily == AddressFamily.InterNetwork);
    }
}