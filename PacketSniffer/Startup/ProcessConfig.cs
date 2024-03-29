using System.Diagnostics;
using System.Reflection;

namespace PacketSniffer.Startup
{
    public static class ProcessConfig
    {
        public static void RunAsProcess(this WebApplicationBuilder builder)
        {
            string appPath = Assembly.GetExecutingAssembly().Location;

            var process = new Process();
            process.StartInfo.FileName = appPath;
            process.StartInfo.CreateNoWindow = true;
            process.StartInfo.UseShellExecute = false;
            
            process.Start();
        }
    }
}
