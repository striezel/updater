/*>
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

using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace updater.software.openjdk_api
{
    /// <summary>
    /// Contains information about an AdoptOpenJDK release.
    /// </summary>
    internal class Release
    {
        /// <summary>
        /// binaries in the given release
        /// </summary>
        [JsonPropertyName("binaries")]
        public List<Binary> Binaries { get; set; }


        /// <summary>
        /// name of the release, e.g. "jdk8u292-b10"
        /// </summary>
        [JsonPropertyName("release_name")]
        public string ReleaseName { get; set; }


        /// <summary>
        /// type of the release, e.g. "ga" for General Availability release
        /// </summary>
        [JsonPropertyName("release_type")]
        public string ReleaseType { get; set; }


        /// <summary>
        /// version information of the release
        /// </summary>
        [JsonPropertyName("version_data")]
        public VersionData VersionData { get; set; }


        /// <summary>
        /// Creates new, empty instance with all data set to null.
        /// </summary>
        public Release()
        {
            Binaries = null;
            ReleaseName = null;
            ReleaseType = null;
            VersionData = null;
        }
    } // class
} // namespace
