using StackExchange.Redis;

namespace PacketSniffer.Startup
{
    public static class StreamConfig
    {
        public static void CreateStreamIfNeeded(this WebApplicationBuilder builder, ConnectionMultiplexer connection, string key)
        {
            var db = connection.GetDatabase();

            try
            {
                var firstEntry = db.StreamInfo(key).FirstEntry.Values.First().ToString();
                if (!firstEntry.Contains(key))
                    db.StreamAdd(key, new RedisValue($"{key}"), new RedisValue("created"));
            }
            catch
            {
                db.StreamAdd(key, new RedisValue($"{key}"), new RedisValue("created"));
            }
        }
    }
}
