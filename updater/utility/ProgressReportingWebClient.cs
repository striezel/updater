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
    /// WebClient that reports download progress to the logging targets.
    /// </summary>
    public class ProgressReportingWebClient : WebClient
    {
        /// <summary>
        /// NLog.Logger for ProgressReportingWebClient
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(ProgressReportingWebClient).FullName);


        /// <summary>
        /// Initializes a new instance of ProgressReportingWebClient.
        /// </summary>
        public ProgressReportingWebClient() : base()
        {
            Start = DateTime.UtcNow;
            DownloadProgressChanged += new DownloadProgressChangedEventHandler(DownloadProgress);
        }


        protected override WebRequest GetWebRequest(Uri address)
        {
            var req = base.GetWebRequest(address) as HttpWebRequest;
            req.AutomaticDecompression = DecompressionMethods.All;
            return req;
        }


        /// <summary>
        /// Time when the current request started.
        /// Should be set manually before the start of each request / download,
        /// or otherwise the timing and the reported progress may be incorrect.
        /// </summary>
        public DateTime Start { get; set; }


        /// <summary>
        /// Calculates the average transfer rate in bytes per second.
        /// </summary>
        /// <param name="BytesReceived">amount of data received since start of the transfer</param>
        /// <returns>Returns the transfer rate in bytes per second.</returns>
        public long BytesPerSecond(long BytesReceived)
        {
            var diff = DateTime.UtcNow - Start;
            return Convert.ToInt64(Math.Round(BytesReceived / diff.TotalSeconds));
        }


        private static void DownloadProgress(object sender, DownloadProgressChangedEventArgs e)
        {
            long bps = (sender as ProgressReportingWebClient).BytesPerSecond(e.BytesReceived);
            if (bps <= 0)
                bps = 1;
            long eta = Convert.ToInt64((e.TotalBytesToReceive - e.BytesReceived) / Convert.ToDouble(bps));
            logger.Info("Progress: {0} of {1} downloaded ({2} %) @ {3}/s, {4}...",
                new object[] { FormatBytes(e.BytesReceived), FormatBytes(e.TotalBytesToReceive),
                    e.ProgressPercentage, FormatBytes(bps), FormatSeconds(eta) });
        }


        /// <summary>
        /// Formats a given number of seconds as a human-friendly string.
        /// </summary>
        /// <param name="seconds">time span in seconds</param>
        /// <returns>Returns the time span as human-friendly string, e.g.
        /// "2min 17s" for 137 seconds.</returns>
        public static string FormatSeconds(long seconds)
        {
            if (seconds < 0)
                return "-" + FormatSeconds(-seconds);
            if (seconds < 60)
                return seconds.ToString() + "s";
            if (seconds < 3600)
            {
                long minutes = seconds / 60;
                long secs = seconds % 60;
                return minutes.ToString() + "min " + secs.ToString() + "s";
            }

            long hours = seconds / 3600;
            return hours.ToString() + "h " + FormatSeconds(seconds - hours * 3600);
        }


        /// <summary>
        /// Formats a number of bytes as a human-friendly string.
        /// </summary>
        /// <param name="bytes">the number of bytes</param>
        /// <returns>Returns a human-friendly string, e.g. "1.5 KB" for 1536 bytes.</returns>
        public static string FormatBytes(long bytes)
        {
            var invariant = System.Globalization.CultureInfo.InvariantCulture;
            if (bytes < 1024)
            {
                return bytes.ToString(invariant) + " bytes";
            }
            if (bytes < 1024*1024)
            {
                return Math.Round(bytes / 1024.0, 2).ToString(invariant) + " KB";
            }

            return Math.Round(bytes / (1024.0 * 1024.0), 2).ToString(invariant) + " MB";
        }
    }
}
