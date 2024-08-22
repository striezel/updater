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

using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using updater.utility;

namespace updater_test.utility
{
    /// <summary>
    /// Contains tests for the ProgressReportingWebClient class.
    /// </summary>
    [TestClass]
    public class ProgressReportingWebClient_Tests
    {
        private static long Epsilon(long x)
        {
            return Math.Sign(x) * x / 100;
        }


        /// <summary>
        /// Tests whether BytesPerSecond() works as expected.
        /// </summary>
        [TestMethod]
        public void Test_BytesPerSecond()
        {

            var client = new ProgressReportingWebClient();

            // Since the BytesPerSecond() method uses the current time for its
            // calculation and we cannot really say how many milliseconds it
            // takes to call the method and perform the calculation, we must
            // allow for a certain delta ("epsilon") here.
            client.Start = DateTime.UtcNow.AddMilliseconds(-500);
            Assert.AreEqual(2000, client.BytesPerSecond(1000), Epsilon(2000));

            client.Start = DateTime.UtcNow.AddMilliseconds(-2500);
            Assert.AreEqual(400, client.BytesPerSecond(1000), Epsilon(400));

            client.Start = DateTime.UtcNow.AddSeconds(-10);
            Assert.AreEqual(1000, client.BytesPerSecond(10000), Epsilon(1000));
        }


        /// <summary>
        /// Tests whether FormatSeconds() works as expected.
        /// </summary>
        [TestMethod]
        public void Test_FormatSeconds()
        {
            var cases = new Dictionary<long, string>(9)
            {
                { 23, "23s" },
                { 59, "59s" },
                { 60, "1min 0s" },
                { 123, "2min 3s" },
                { 1234, "20min 34s" },
                { 3599, "59min 59s" },
                { 3600, "1h 0s" },
                { 3678, "1h 1min 18s" },
                { 7425, "2h 3min 45s" }
            };

            foreach (var item in cases)
            {
                Assert.AreEqual<string>(item.Value, ProgressReportingWebClient.FormatSeconds(item.Key));
            }
        }


        /// <summary>
        /// Tests whether FormatBytes() works as expected.
        /// </summary>
        [TestMethod]
        public void Test_FormatBytes()
        {
            var cases = new Dictionary<long, string>(10)
            {
                { 512, "512 bytes" },
                { 1024, "1 KB" },
                { 1536, "1.5 KB" },
                { 2816, "2.75 KB" },
                { 4321, "4.22 KB" },
                { 10752, "10.5 KB" },
                { 53504, "52.25 KB" },
                { 1024 * 1024, "1 MB" },
                { 2 * 1024 * 1024, "2 MB" },
                { 337064755, "321.45 MB" },
            };

            foreach (var item in cases)
            {
                Assert.AreEqual<string>(item.Value, ProgressReportingWebClient.FormatBytes(item.Key));
            }
        }
    } // class
} // namespace
