/*
    This file is part of the updater command line interface.
    Copyright (C) 2024  Dirk Stolle

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
    /// WebClient that automatically adds automatic decompression.
    /// </summary>
    public class AutoDecompressWebClient : WebClient
    {
        /// <summary>
        /// Initializes a new instance of ProgressReportingWebClient.
        /// </summary>
        public AutoDecompressWebClient() : base()
        {
        }


        protected override WebRequest GetWebRequest(Uri address)
        {
            if (address.OriginalString.ToLowerInvariant().Contains("filezilla"))
            {
                var req = base.GetWebRequest(address) as HttpWebRequest;
                req.AutomaticDecompression = DecompressionMethods.All;
                return req;
            }
            else
            {
                return base.GetWebRequest(address);
            }
        }
    }
}
