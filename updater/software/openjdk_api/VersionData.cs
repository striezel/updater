/*
    This file is part of the updater command line interface.
    Copyright (C) 2021, 2025  Dirk Stolle

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

using System.Text.Json.Serialization;

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
        [JsonPropertyName("major")]
        public int Major { get; set; }

        /// <summary>
        /// minor version number, e.g. the 0 (zero) in 8.0.292+10
        /// </summary>
        [JsonPropertyName("minor")]
        public int Minor { get; set; }

        /// <summary>
        /// security patch level, e.g. the 292 in 8.0.292+10 or 8u292-b10
        /// </summary>
        [JsonPropertyName("security")]
        public int Security { get; set; }

        /// <summary>
        /// build number, e.g. the 10 in 8.0.292+10 or 8u292-b10
        /// </summary>
        [JsonPropertyName("build")]
        public int Build { get; set; }


        /// <summary>
        /// Semantic Versioning string, e.g. "8.0.292+10"
        /// </summary>
        [JsonPropertyName("semver")]
        public string SemVer { get; set; }


        /// <summary>
        /// build number to indicate missing information
        /// </summary>
        internal const int MissingBuildNumber = -1;


        /// <summary>
        /// Creates "empty" object with no meaningful data.
        /// </summary>
        public VersionData()
        {
            Major = MissingBuildNumber;
            Minor = MissingBuildNumber;
            Security = MissingBuildNumber;
            Build = MissingBuildNumber;
            SemVer = null;
        }
    } // class
} // namespace
