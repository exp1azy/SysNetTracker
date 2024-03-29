using PacketSniffer.Resources;
using StackExchange.Redis;

namespace PacketSniffer.Startup
{
    public static class RedisConfig
    {
        public static ConnectionMultiplexer AddRedis(this WebApplicationBuilder builder)
        {
            var connectionString = builder.Configuration["RedisConnection"];
            if (string.IsNullOrEmpty(connectionString))
                throw new ArgumentNullException(Error.FailedToReadRedisConnectionString);

            var connection = ConnectionMultiplexer.Connect(connectionString);

            builder.Services.AddSingleton(sp => connection);

            return connection;
        }
    }
}
