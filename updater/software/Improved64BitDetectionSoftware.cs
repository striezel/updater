/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2024  Dirk Stolle

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
using updater.data;

namespace updater.software
{
    /// <summary>
    /// Abstract base class for software that needs a little bit of help with the
    /// proper detection of 64-bit versions of itself.
    /// </summary>
    public abstract class Improved64BitDetectionSoftware : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        /// <param name="exeBaseName">the base name of the executable to use during checks, e.g. "filezilla.exe"</param>
        protected Improved64BitDetectionSoftware(bool autoGetNewer, string exeBaseName)
            : base(autoGetNewer)
        {
            executableBaseName = exeBaseName;
        }


        /// <summary>
        /// Checks whether the software is in the list of detected software.
        /// </summary>
        /// <param name="detected">list of detected software on the system</param>
        /// <param name="autoGetNew">whether to automatically get new software information</param>
        /// <param name="result">query result where software will be added, if it is in the detection list</param>
        public override void detectionQuery(List<DetectedSoftware> detected, bool autoGetNew, List<QueryEntry> result)
        {
            // 32-bit systems use normal detection.
            if (!Environment.Is64BitOperatingSystem)
            {
                base.detectionQuery(detected, autoGetNew, result);
                return;
            }
            // 64-bit systems might need adjustments.
            var resultBase = new List<QueryEntry>();
            base.detectionQuery(detected, autoGetNew, resultBase);
            foreach (var item in resultBase)
            {
                if (string.IsNullOrWhiteSpace(item.detected.installPath))
                    continue;
                // Remove enclosing quotes.
                if (item.detected.installPath.StartsWith("\"") && item.detected.installPath.EndsWith("\""))
                {
                    item.detected.installPath = item.detected.installPath[1..^1];
                }
                // See if we need to adjust the type for the 64-bit variant.
                string exePath = System.IO.Path.Combine(item.detected.installPath, executableBaseName);
                utility.PEFormat format = utility.PortableExecutable.determineFormat(exePath);
                if ((format == utility.PEFormat.PE64) && (item.type != ApplicationType.Bit64))
                {
                    item.type = ApplicationType.Bit64;
                    item.detected.appType = ApplicationType.Bit64;
                }
            }
            result.AddRange(resultBase);
        }


        /// <summary>
        /// base name of the executable to check in the installation directory
        /// </summary>
        private readonly string executableBaseName;
    } // class
} // namespace
