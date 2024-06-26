﻿using Microsoft.AspNetCore.Mvc;
using WebSpectre.Shared.Agents;

namespace PacketSniffer.Controllers
{
    /// <summary>
    /// Контроллер агента.
    /// </summary>
    /// <remarks>
    /// Конструктор.
    /// </remarks>
    /// <param name="pcap">Сервис агента.</param>
    [ApiController]
    [Route("[controller]")]
    public class PcapController(PcapAgent pcap) : ControllerBase
    {
        private readonly PcapAgent _capAgent = pcap;

        /// <summary>
        /// Информация о хосте.
        /// </summary>
        /// <returns>Возвращает <see cref="HostInfo"/></returns>
        [HttpGet("info")]
        public IActionResult Info() => Ok(_capAgent.GetHostInfo());

        /// <summary>
        /// Запуск захвата сетевого трафика.
        /// </summary>
        /// <param name="a">Сетевой адаптер.</param>
        /// <returns></returns>
        [HttpGet("start")]
        public IActionResult Start([FromQuery] string a) 
        {
            try
            {
                _capAgent.Start(a);
            }
            catch (ApplicationException ex)
            {
                return Forbid(ex.Message);
            }

            return Ok();
        }

        /// <summary>
        /// Остановка захвата сетевого трафика.
        /// </summary>
        /// <returns></returns>
        [HttpGet("stop")]
        public IActionResult Stop()
        {
            _capAgent.Stop();

            return Ok();
        }
    }
}
