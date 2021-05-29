/*
    This file is part of the updater command line interface.
    Copyright (C) 2021  Dirk Stolle

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

using System;
using System.Net;

namespace updater.utility
{
    /// <summary>
    /// Extension of the WebClient class that allows to set a timeout via `TimeoutMillis`.
    /// Default timeout is 25 seconds.
    /// </summary>
    public class TimelyWebClient: WebClient
    {
        /// <summary>
        /// Default constructor, sets timeout to 25 seconds.
        /// </summary>
        public TimelyWebClient():
            base()
        {
            TimeoutMillis = 25000; // 25 seconds default
        }


        /// <summary>
        /// Timeout for requests in milliseconds.
        /// </summary>
        public int TimeoutMillis { get; set; }


        protected override WebRequest GetWebRequest(Uri uri)
        {
            var request = base.GetWebRequest(uri);
            request.Timeout = TimeoutMillis;
            return request;
        }
    } // class
} // namespace
