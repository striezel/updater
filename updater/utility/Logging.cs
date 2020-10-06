/*
    This file is part of the updater command line interface.
    Copyright (C) 2017  Dirk Stolle

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
using System.IO;

namespace updater.utility
{
    /// <summary>
    /// Handles some logging-related tasks.
    /// </summary>
    internal static class Logging
    {
        /// <summary>
        /// Initializes the configuration of NLog.LogManager with logging to console + file.
        /// </summary>
        public static void initialize()
        {
            // create configuration object
            var config = new NLog.Config.LoggingConfiguration();

            // create targets and add them to the configuration 
            // --- console
            var consoleTarget = new NLog.Targets.ColoredConsoleTarget();
            config.AddTarget("console", consoleTarget);
            // --- file
            var fileTarget = new NLog.Targets.FileTarget();
            config.AddTarget("file", fileTarget);

            // set target properties 
            consoleTarget.Layout = @"${date:format=yyyy-MM-dd HH\:mm\:ss} - ${message}";
            fileTarget.FileName = getLogFileName();
            fileTarget.Layout = @"${date:format=yyyy-MM-dd HH\:mm\:ss} [${logger}] ${message}";

            // define rules
            var rule1 = new NLog.Config.LoggingRule("*", NLog.LogLevel.Debug, consoleTarget);
            config.LoggingRules.Add(rule1);
            var rule2 = new NLog.Config.LoggingRule("*", NLog.LogLevel.Debug, fileTarget);
            config.LoggingRules.Add(rule2);

            // activate the configuration
            NLog.LogManager.Configuration = config;
        }


        /// <summary>
        /// Gets a log file name for the application.
        /// </summary>
        /// <returns>Returns a log file name that includes the current date / time.</returns>
        private static string getLogFileName()
        {
            string datePart = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            return Path.Combine(Path.GetTempPath(), "updater-cli-log_" + datePart + ".txt");
        }
    } // class
} // namespace
