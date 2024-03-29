using StackExchange.Redis;

namespace PacketSniffer
{
    /// <summary>
    /// Сервис, представляющий логику для взаимодействия с сервером Redis.
    /// </summary>
    public class RedisService
    {
        private IDatabase _db;
        private ConnectionMultiplexer? _connection;
        private RedisKey _key;

        /// <summary>
        /// Конструктор.
        /// </summary>
        public RedisService(ConnectionMultiplexer connection, RedisKey key)
        {
            _connection = connection;
            _db = _connection.GetDatabase();
            _key = key;
        }

        /// <summary>
        /// Добавляет массив <see cref="NameValueEntry"/> в поток Redis по ключу <see cref="RedisKey"/>.
        /// </summary>
        /// <param name="key">Ключ потока.</param>
        /// <param name="streamPairs">Данные.</param>
        /// <returns></returns>
        public async Task StreamAddAsync(NameValueEntry[] streamPairs) =>
            await _db.StreamAddAsync(_key, streamPairs);
    }
}
