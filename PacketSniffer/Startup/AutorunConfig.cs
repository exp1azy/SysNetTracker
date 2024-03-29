using Microsoft.Win32;
using Serilog;
using System.Reflection;
using System.Security;

namespace PacketSniffer.Startup
{
    public static class AutorunConfig
    {
        public static void StartWithWindows(this WebApplicationBuilder builder)
        {
            string appPath = Assembly.GetExecutingAssembly().Location;

            try
            {
                // Запускать от имени администратора!
                using (var key = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", true))
                {
                    if (key.GetValue("PacketSniffer") == null)
                        key.SetValue("PacketSniffer", appPath);
                }
            }
            catch (SecurityException ex)
            { 
                Log.Logger.Error(ex.Message);
            }   
        }
    }
}
