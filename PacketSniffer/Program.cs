using PacketSniffer.Resources;
using PacketSniffer.Startup;
using Serilog;

namespace PacketSniffer
{
    public static class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            builder.RunAsProcess();
            builder.StartWithWindows();

            Log.Logger = new LoggerConfiguration()
                .WriteTo.EventLog("PacketSniffer", manageEventSource: true)
                .CreateLogger();

            builder.Services.AddCors(o => o.AddDefaultPolicy(p =>
            {
                p.AllowAnyHeader();
                p.AllowAnyMethod();
                p.AllowAnyOrigin();
            }));

            var host = $"host_{Environment.MachineName.ToLower()}";
            int port;

            try
            {
                port = builder.Configuration.GetPort();
            }
            catch
            {
                port = 59037;
            }

            var connection = builder.AddRedis();

            builder.CreateStreamIfNeeded(connection, host);

            builder.WebHost.UseUrls($"https://{host}:{port}");

            builder.Services.AddSingleton<PcapAgent>();
            builder.Services.AddTransient(sp => new RedisService(connection, host));

            builder.Services.AddAuthentication();

            builder.Services.AddControllers();

            var app = builder.Build();

            app.UseRouting();

            app.UseCors();

            app.MapControllers();

            app.Run();
        }

        public static int GetPort(this IConfiguration config)
        {
            _ = int.TryParse(config?["Port"], out var port);
            if (port <= 0)
                throw new ApplicationException(Error.FailedToReadPort);

            return port;
        }
    }
}
