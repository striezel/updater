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

namespace updater.software.openjdk_api
{
    /// <summary>
    /// Contains basic version information for an OpenJDK release.
    /// </summary>
    internal class VersionData
    {
        /// <summary>
        /// major version number, e.g. the 8 in 8.0.292+10 or 8u292-b10
        /// </summary>
        public int major { get; set; }

        /// <summary>
        /// minor version number, e.g. the 0 (zero) in 8.0.292+10
        /// </summary>
        public int minor { get; set; }

        /// <summary>
        /// security patch level, e.g. the 292 in 8.0.292+10 or 8u292-b10
        /// </summary>
        public int security { get; set; }

        /// <summary>
        /// build number, e.g. the 10 in 8.0.292+10 or 8u292-b10
        /// </summary>
        public int build { get; set; }


        /// <summary>
        /// Semantic Versioning string, e.g. "8.0.292+10"
        /// </summary>
        public string semver { get; set; }


        /// <summary>
        /// build number to indicate missing information
        /// </summary>
        internal const int MissingBuildNumber = -1;


        /// <summary>
        /// Creates "empty" object with no meaningful data.
        /// </summary>
        public VersionData()
        {
            major = MissingBuildNumber;
            minor = MissingBuildNumber;
            security = MissingBuildNumber;
            build = MissingBuildNumber;
            semver = null;
        }
    } // class
} // namespace
