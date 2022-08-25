/*
    This file is part of the updater command line interface.
    Copyright (C) 2022  Dirk Stolle

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

using System.Net.Http;

namespace updater
{
    /// <summary>
    /// Provides a HttpClient instance for reuse among requests.
    /// </summary>
    internal static class HttpClientProvider
    {
        private static readonly HttpClient client = new HttpClient();

        /// <summary>
        /// Gets the HttpClient instance.
        /// </summary>
        /// <returns>Returns the HttpClient instance.</returns>
        public static HttpClient Provide()
        {
            return client;
        }
    }
}
