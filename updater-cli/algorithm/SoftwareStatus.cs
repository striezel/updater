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
using System.Text.RegularExpressions;

namespace updater_cli.algorithm
{
    public class SoftwareStatus
    {
        /// <summary>
        /// queries the software status
        /// </summary>
        /// <returns>Returns a list of query entries.</returns>
        public static List<QueryEntry> query()
        {
            var detected = DetectorRegistry.detect();
            if (null == detected)
                return null;
            detected.Sort();

            var result = new List<QueryEntry>();

            var all = All.get();
            foreach (var item in all)
            {
                var info = item.info();
                if (Environment.Is64BitOperatingSystem && !string.IsNullOrWhiteSpace(info.match64Bit))
                {
                    Regex regularExp = new Regex(info.match64Bit, RegexOptions.IgnoreCase);
                    int idx = detected.FindIndex(x => regularExp.IsMatch(x.displayName) && !string.IsNullOrWhiteSpace(x.displayVersion));
                    if (idx >= 0)
                    {
                        //found it
                        bool needsUpdate = (string.Compare(detected[idx].displayVersion, info.newestVersion, true) < 0);
                        result.Add(new QueryEntry(item, detected[idx], needsUpdate));
                    } //if match was found
                } //if 64 bit expression does exist and we are on a 64 bit system
                if (!string.IsNullOrWhiteSpace(info.match32Bit))
                {
                    Regex regularExp = new Regex(info.match32Bit, RegexOptions.IgnoreCase);
                    int idx = detected.FindIndex(x => regularExp.IsMatch(x.displayName) && !string.IsNullOrWhiteSpace(x.displayVersion));
                    if (idx >= 0)
                    {
                        //found it
                        bool needsUpdate = (string.Compare(detected[idx].displayVersion, info.newestVersion, true) < 0);
                        result.Add(new QueryEntry(item, detected[idx], needsUpdate));
                    } //if match was found
                } //if 32 bit expression does exist
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
            const string cCurrent = "current";
            const string cNewest = "newest";
            const string cVersion = "version";
            const string cUpdatable1 = "can be";
            const string cUpdatable2 = "updated";

            //determine longest entries
            int maxSoftwareNameLength = cName.Length;
            int maxCurrentVersionLength = Math.Max(cCurrent.Length, cVersion.Length);
            int maxNewestVersionLength = Math.Max(cNewest.Length, cVersion.Length);
            int maxUpdatableLength = Math.Max(cUpdatable1.Length, cUpdatable2.Length); ;
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
                + "-+-" + "-".PadRight(maxCurrentVersionLength, '-') + "-+-"
                + "-".PadRight(maxNewestVersionLength, '-') + "-+-"
                + "-".PadRight(maxUpdatableLength, '-') + "-+"
                + Environment.NewLine;
            string header = "| " + cName.PadRight(maxSoftwareNameLength)
                + " | " + cCurrent.PadRight(maxCurrentVersionLength) + " | "
                + cNewest.PadRight(maxNewestVersionLength) + " | "
                + cUpdatable1.PadRight(maxUpdatableLength) + " |"
                + Environment.NewLine
                + "| " + " ".PadRight(maxSoftwareNameLength)
                + " | " + cVersion.PadRight(maxCurrentVersionLength) + " | "
                + cVersion.PadRight(maxNewestVersionLength) + " | "
                + cUpdatable2.PadRight(maxUpdatableLength) + " |"
                + Environment.NewLine;
            foreach (var item in query)
            {
                var info = item.software.info();
                //name of software
                output += "| " + info.Name.PadRight(maxSoftwareNameLength) + " | ";
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
    } //class
} //namespace
