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
using System.Collections.Generic;
using updater_cli.data;
using updater_cli.detection;
using updater_cli.software;

namespace updater_cli.operations
{
    /// <summary>
    /// class to query the status of installed software
    /// </summary>
    public class SoftwareStatus : IOperation
    {
        /// <summary>
        /// default constructor
        /// </summary>
        public SoftwareStatus(bool _getNewer, bool withAurora)
        {
            includeAurora = withAurora;
            autoGetNewer = _getNewer;
        }

        
        /// <summary>
        /// queries the software status
        /// </summary>
        /// <param name="withAurora">Whether or not Firefox Developer Edition
        /// (aurora channel) shall be included, too. Default is false, because
        /// this increases time of the query by quite a bit (several seconds).</param>
        /// <returns>Returns a list of query entries.</returns>
        public static List<QueryEntry> query(bool autoGetNewer, bool withAurora)
        {
            var detected = DetectorRegistry.detect();
            if (null == detected)
                return null;
            detected.Sort();

            var result = new List<QueryEntry>();

            var all = All.get(false, withAurora);
            foreach (var item in all)
            {
                item.detectionQuery(detected, autoGetNewer, result);
            } //foreach
            return result;
        }


        /// <summary>
        /// transforms a query result into a string that is suitable for output
        /// on the console
        /// </summary>
        /// <param name="query">query result</param>
        /// <returns>Returns a string that can be written to the console.
        /// Returns null, if an error occurred.</returns>
        public static string toConsoleOutput(List<QueryEntry> query)
        {
            if (null == query)
                return null;
            if (query.Count == 0)
            {
                return "No known software was found.";
            }

            const string cName = "Software";
            const string cAppType = "type";
            const string cCurrent = "current";
            const string cNewest = "newest";
            const string cVersion = "version";
            const string cUpdatable1 = "can be";
            const string cUpdatable2 = "updated";

            //determine longest entries
            int maxSoftwareNameLength = cName.Length;
            int maxAppTypeLength = Math.Max(cAppType.Length, utility.Strings.appTypeToString(ApplicationType.Bit32).Length);
            int maxCurrentVersionLength = Math.Max(cCurrent.Length, cVersion.Length);
            int maxNewestVersionLength = Math.Max(cNewest.Length, cVersion.Length);
            int maxUpdatableLength = Math.Max(cUpdatable1.Length, cUpdatable2.Length);
            foreach (var item in query)
            {
                var info = item.software.info();
                if (!string.IsNullOrWhiteSpace(info.Name) && info.Name.Length > maxSoftwareNameLength)
                    maxSoftwareNameLength = info.Name.Length;
                if (!string.IsNullOrWhiteSpace(item.detected.displayVersion) && item.detected.displayVersion.Length > maxCurrentVersionLength)
                    maxCurrentVersionLength = item.detected.displayVersion.Length;
                if (!string.IsNullOrWhiteSpace(info.newestVersion) && info.newestVersion.Length > maxNewestVersionLength)
                    maxNewestVersionLength = info.newestVersion.Length;
                int len = utility.Strings.boolToYesNo(item.needsUpdate).Length;
                if (len > maxUpdatableLength)
                    maxUpdatableLength = len;
            } //foreach

            //get output
            string output = "";
            string fullLine = "+-" + "-".PadRight(maxSoftwareNameLength, '-')
                + "-+-" + "-".PadRight(maxAppTypeLength, '-') + "-+-"
                + "-".PadRight(maxCurrentVersionLength, '-') + "-+-"
                + "-".PadRight(maxNewestVersionLength, '-') + "-+-"
                + "-".PadRight(maxUpdatableLength, '-') + "-+"
                + Environment.NewLine;
            string header = "| " + cName.PadRight(maxSoftwareNameLength)
                + " | " + cAppType.PadRight(maxAppTypeLength) + " | "
                + cCurrent.PadRight(maxCurrentVersionLength) + " | "
                + cNewest.PadRight(maxNewestVersionLength) + " | "
                + cUpdatable1.PadRight(maxUpdatableLength) + " |"
                + Environment.NewLine
                + "| " + " ".PadRight(maxSoftwareNameLength)
                + " | " + " ".PadRight(maxAppTypeLength) + " | "
                + cVersion.PadRight(maxCurrentVersionLength) + " | "
                + cVersion.PadRight(maxNewestVersionLength) + " | "
                + cUpdatable2.PadRight(maxUpdatableLength) + " |"
                + Environment.NewLine;
            foreach (var item in query)
            {
                var info = item.software.info();
                //name of software
                output += "| " + info.Name.PadRight(maxSoftwareNameLength) + " | ";
                //application type
                output += utility.Strings.appTypeToString(item.type).PadRight(maxAppTypeLength) + " | ";
                //currently installed version
                if (!string.IsNullOrWhiteSpace(item.detected.displayVersion))
                output += item.detected.displayVersion.PadRight(maxCurrentVersionLength);
                else
                    output += "???".PadRight(maxCurrentVersionLength);
                //newest version
                output += " | " + info.newestVersion.PadRight(maxNewestVersionLength) + " | ";
                //updatable
                output += utility.Strings.boolToYesNo(item.needsUpdate)
                    .PadRight(maxUpdatableLength) + " |" + Environment.NewLine;
            } //foreach
            output = fullLine + header + fullLine + output + fullLine;
            return output;
        }


        /// <summary>
        /// Flag that indicates whether or not Firefox Developer Edition
        /// (aurora channel) shall be included, too. Default is false, because
        /// this increases time of the query by quite a bit (several seconds).
        /// </summary>
        public bool includeAurora;


        /// <summary>
        /// whether to automatically get newer software info, if possible
        /// </summary>
        public bool autoGetNewer;


        /// <summary>
        /// shows the query result in the console
        /// </summary>
        /// <returns>Returns zero.</returns>
        public int perform()
        {
            //get software status
            var status = query(autoGetNewer, includeAurora);
            string output = toConsoleOutput(status);
            Console.Write(output);
            return 0;
        }
    } //class
} //namespace
